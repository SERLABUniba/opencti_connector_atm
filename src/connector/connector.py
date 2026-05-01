import uuid
import json
import copy
import types
import stix2
from datetime import datetime, timezone
from typing import Optional
from markdownify import markdownify as md
from pycti import OpenCTIConnectorHelper
from connector.settings import ConnectorSettings
from atm_client import ATMClient
import requests

#This dictionary is useful to map the Tactics on Mitre and on the ATM KB
ATM_PHASE_TO_KILLCHAIN = {
    "reconnaissance":           "mitre-attack",
    "resource_development":     "mitre-attack",
    "initial_access":           "mitre-attack",
    "execution":                "mitre-attack",
    "persistence":              "mitre-attack",
    "privilege_escalation":     "mitre-attack",
    "defense_evasion":          "mitre-attack",
    "credential_access":        "mitre-attack",
    "discovery":                "mitre-attack",
    "lateral_movement":         "mitre-attack",
    "collection":               "mitre-attack",
    "command_and_control":      "mitre-attack",
    "exfiltration":             "mitre-attack",
    "impact":                   "mitre-attack",
    "manipulate_environment":   "atm-automotive",
    "affect_vehicle_function":  "atm-automotive",
    "vehicle_network_access":   "atm-automotive",
    "ecu_compromise":           "atm-automotive",
    "sensor_manipulation":      "atm-automotive",
    "firmware_manipulation":    "atm-automotive",
    "can_bus_attack":           "atm-automotive",
    "ota_attack":               "atm-automotive",
}

# Types without "created_by_ref" parameter
SKIP_AUTHOR_TYPES = {
    "bundle",
    "relationship",
    "x-mitre-matrix",
}


def _patched_initiate_work(
    self, connector_id: str, friendly_name: str, is_multipart: bool = False
) -> Optional[str]:
    """
    This function query the database without the 'is_multipart'. 
    If you are using a version of OpenCTI <= 7.260428.0 use this method, otherwise comment it.

    :param connector_id: the connector id
    :param friendly_name: the friendly name for the work
    :param is_multipart: indicates whether multiple calls to `add_expectations`
                                are to be expected during the lifetime of the work.
                                In consequence the work won't automatically
                                transition to `complete` when the number of calls
                                to `report_expectation` matches the expectations
                                but only when an explicit call to `to_processed`
                                is made.
                                Should be set to `True` when sending multiple
                                STIX bundles consecutively via `send_stix2_bundle`
    :return: the id of the work added
    """

    query = """
        mutation WorkAdd($connectorId: String!, $friendlyName: String!) {
            workAdd(connectorId: $connectorId, friendlyName: $friendlyName) {
                id
            }
        }
    """
    work = self.api.query(query, {
        "connectorId": connector_id,
        "friendlyName": friendly_name,
    })
    return work["data"]["workAdd"]["id"]


class ATMConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = ATMClient(
            stix_url=config.atm.stix_url
        )
        # Patch initiate_work for compatibility
        self.helper.api.work.initiate_work = types.MethodType(
            _patched_initiate_work, self.helper.api.work
        )

        # Generate l'ID STIX deterministico per l'autore
        self.author_stix_id = (
            f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, self.config.atm.author_name)}"
        )

    def _build_author_object(self) -> dict:
        """
        This function builds the STIX Identity object representing the connector author.
        This identity will be set as 'created_by_ref' on all imported objects, allowing OpenCTI to track data provenance per connector/user.
        :return: the dictionary coresponding to the creator of the Bundle
        """
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.author_stix_id,
            "name": self.config.atm.author_name,
            "identity_class": self.config.atm.author_identity_class,
            "description": (
                "Connector identity for ATM Automotive ISAC data. "
                "All objects imported by this connector are owned by this identity."
            ),
            "external_references": [
                {
                    "source_name": "AutoISAC ATM",
                    "url": "https://atm.automotiveisac.com",
                }
            ],
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
        }

    def _fix_kill_chain_phases(self, obj: dict) -> dict:
        """
        This funtion replace 'not applicable' kill_chain_name with correct mapping.
        :param obj: the dictionary corespoding to a specific attack pattern
        :return: the dictionary corespoding to the specific attack pattern with 
                the 'kill chian' information changed ("mitre-attack" or "atm-automotive")
        """
        phases = obj.get("kill_chain_phases", [])
        if not phases:
            return obj

        fixed_phases = []
        for phase in phases:
            phase_name = phase.get("phase_name", "")
            current_kc = phase.get("kill_chain_name", "")

            if current_kc == "not applicable":
                mapped_kc = ATM_PHASE_TO_KILLCHAIN.get(
                    phase_name,
                    self.config.atm.atm_kill_chain_name,
                )
            else:
                mapped_kc = current_kc

            fixed_phases.append({
                "kill_chain_name": mapped_kc,
                "phase_name": phase_name,
            })

        obj["kill_chain_phases"] = fixed_phases
        return obj

    def _process_bundle(self, bundle: dict) -> tuple[dict, dict]:
        """
        Process the entire bundle:
        1. Inject author identity as first object
        2. Set created_by_ref on all applicable objects (with respect to the SKIP_AUTHOR_TYPES set)
        3. Fix kill_chain_phases on attack-pattern objects (with respect to the ATM_PHASE_TO_KILLCHAIN set)
        :param bundle: the entire STIX Bundle
        :return : the tuple compose by: the bundle processed and the statistics related to:
                the attack_patterns_fixed, tactics, campaigns, relationships, other,author_injected
        """
        processed = copy.deepcopy(bundle)
        stats = {
            "attack_patterns_fixed": 0,
            "tactics": 0,
            "campaigns": 0,
            "relationships": 0,
            "other": 0,
            "author_injected": 0,
        }

        # Prepend author identity as first object in the bundle
        author_obj = self._build_author_object()
        processed["objects"].insert(0, author_obj)

        for obj in processed.get("objects", []):
            #Changing the field "Description" in markdown

            if obj.get("description"):
                obj["description"] = md(obj.get("description"))
                obj["description"] = obj.get("description").replace('\n'," ")

            obj_type = obj.get("type", "")

            # Inject created_by_ref on all applicable objects
            if obj_type not in SKIP_AUTHOR_TYPES and obj.get("id") != self.author_stix_id:
                obj["created_by_ref"] = self.author_stix_id
                stats["author_injected"] += 1

            # Fix kill chain on attack patterns
            if obj_type == "attack-pattern":
                self._fix_kill_chain_phases(obj)
                stats["attack_patterns_fixed"] += 1
            elif obj_type == "x-mitre-tactic":
                stats["tactics"] += 1
            elif obj_type == "campaign":
                stats["campaigns"] += 1
            elif obj_type == "relationship":
                stats["relationships"] += 1
            else:
                stats["other"] += 1

        self.helper.log_info(
            f"Bundle processed — "
            f"attack-patterns: {stats['attack_patterns_fixed']}, "
            f"tactics: {stats['tactics']}, "
            f"campaigns: {stats['campaigns']}, "
            f"relationships: {stats['relationships']}, "
            f"author injected on: {stats['author_injected']} objects."
        )

        return processed, stats

    def _run_once(self):
        """
        This function si useful to: 
            1) Read the STIX Bundle from ATM, 
            2) Send the STIX Bundle to OpenCTI (updating the work status),
            3) Update the info related to import (i.e., "last_run")
        """

        work_id = None
        self.helper.log_info("Starting import from ATM Automotive ISAC...")
        try:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "ATM Automotive ISAC — importing TTPs"
            )
            self.helper.log_info(f"Work initiated with ID: {work_id}")

            #Getting the STIX Bundle
            bundle = self.client.get_stix_bundle()
            total_objects = len(bundle.get("objects", []))
            self.helper.log_info(f"Received {total_objects} STIX objects from ATM.")
            
            # Processing the Bundle
            processed_bundle, stats = self._process_bundle(bundle)

            # Sending the Bundle to OpenCTI
            self.helper.send_stix2_bundle(
                json.dumps(processed_bundle),
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )

            # Updating the helper state - in the "Details" panel
            self.helper.set_state({
                "last_run": datetime.now(timezone.utc).isoformat(),
                "last_count": total_objects,
                "last_stats": stats,
            })
            # Updating the helper state - worked processed
            self.helper.api.work.to_processed(
                work_id,
                (
                    f"ATM Automotive ISAC: successfully imported {total_objects} objects. "
                    f"Author identity: {self.config.atm.author_name}. "
                    f"Attack patterns fixed: {stats['attack_patterns_fixed']}, "
                    f"Campaigns: {stats['campaigns']}."
                )
            )
            # Updating the the import status
            self.helper.log_info(
                f"Import completed successfully: {total_objects} objects processed."
            )

        except Exception as e:
            self.helper.log_error(
                f"An unexpected error occurred during import: {e}"
            )
            if work_id:
                self.helper.api.work.to_processed(
                    work_id,
                    f"Import failed with error: {str(e)}",
                    in_error=True,
                )
            raise

    def run(self):
        """
        This function run the connector's features
        """

        self.helper.log_info("Starting the ATM Automotive ISAC connector.")
        self.helper.schedule_iso(
            message_callback=self._run_once,
            duration_period=str(self.config.connector.duration_period),
        )