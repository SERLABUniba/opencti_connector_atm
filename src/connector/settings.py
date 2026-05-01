from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString
)
from pydantic import Field, HttpUrl

class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    #This field is for the ID of the Connector, the same in the .env file
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="93bdd98f-72f9-4076-8f8a-8cc117c7833d",
    )
    #This field is for the scope of the Connector, as in the .enf file
    scope: ListFromString = Field(
        description="The scope of the connector. Only these object types will be imported on OpenCTI.",
        default=[
            "attack-pattern",
            "x-mitre-tactic",
            "x-mitre-matrix",
            "campaign",
            "relationship"
        ],
    )
    #This field is for the name of the connector
    name: str = Field(
        description="The name of the connector.",
        default="[C] ATM Automotive ISAC Connector",
    )
    #This field is for the delta time between to runs of the connector
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=7),
    )

class ATMConfig(BaseConfigModel):
    #This field is for the path of the json file
    stix_url: str = Field(
    default="/app/data/latest_atm.json",
    )   
    #This field is for the confidence level (by default for the external imports is 75)
    confidence_level: int = Field(
        description="Confidence level for imported objects (0-100).",
        default=75,
    )
    #This field is for the type of the kill chain
    mitre_kill_chain_name: str = Field(
        description="Kill chain name for MITRE-shared tactics.",
        default="mitre-attack",
    )
    #This field is for the type of the kill chain
    atm_kill_chain_name: str = Field(
        description="Kill chain name for ATM-specific tactics.",
        default="atm-automotive",
    )
    #This field is for the author of the KB, so the user in OpenCTI
    author_name: str = Field(
        description="Name of the identity that will own imported objects.",
        default="ATM Automotive ISAC Connector",
    )
    #This field is for the type of the author
    author_identity_class: str = Field(
        description="STIX identity class for the author.",
        default="system",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    atm: ATMConfig = Field(
        default_factory=ATMConfig
    )