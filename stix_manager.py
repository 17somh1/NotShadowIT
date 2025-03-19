from stix2 import ExternalReference, ObservedData, Bundle
import json


class STIXManager:
    """
    Handles the creation of STIX objects and bundles.
    """

    def __init__(self, helper):
        self.helper = helper

    def create_stix_bundle(self, observable, enrichment_data, url):
        """
        Creates a STIX bundle for the enriched observable.
        """
        external_ref = ExternalReference(
            source_name="Enrichment Data",
            url=url,
            description=json.dumps(enrichment_data, indent=2)
        )

        stix_obs = ObservedData(
            object_refs=[observable["id"]],
            first_observed=self.helper.api.get_current_time(),
            last_observed=self.helper.api.get_current_time(),
            number_observed=1,
            external_references=[external_ref]
        )

        return Bundle(objects=[stix_obs])