import requests
import json

class ATMClient:
    def __init__(self, stix_url: str):
        self.stix_url = stix_url

    def get_stix_bundle(self) -> dict:
        """
        This function retreive the complete STIX bundle from local folder.
        :return: the json coresponding to the STIX Bundle
        """
        file_path = self.stix_url
        with open(file_path, "r") as f:
            bundle = json.load(f)
        
        if bundle.get("type") != "bundle":
            raise ValueError("Not a valid STIX bundle.")
        if not bundle.get("objects"):
            raise ValueError("STIX bundle is empty.")

        return bundle