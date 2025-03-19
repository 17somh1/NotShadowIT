import logging
from pycti import OpenCTIConnectorHelper
from censys.search import CensysHosts, CensysCerts
from config_manager import ConfigManager
from stix_manager import STIXManager

logger = logging.getLogger(__name__)


class CensysClient:
    """
    Handles interactions with the Censys API for enriching observables.
    """

    def __init__(self, api_id, api_secret):
        """
        Initializes the Censys API clients using the provided credentials.
        """
        try:
            self.censys_hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
            self.censys_certs = CensysCerts(api_id=api_id, api_secret=api_secret)
        except Exception as e:
            logger.critical(f"Failed to initialize Censys API clients: {e}")
            exit(1)

    def enrich_ip(self, ip_address):
        """
        Enriches an IP address using Censys Hosts API.
        """
        try:
            host = self.censys_hosts.view(ip_address)
            return {
                "services": host.get("services", []),
                "location": host.get("location", {}),
                "autonomous_system": host.get("autonomous_system", {})
            }
        except Exception as e:
            logger.error(f"IP enrichment failed: {e}")
            return None

    def enrich_domain(self, domain):
        """
        Enriches a domain name using Censys Certificates API.
        """
        try:
            certs = list(self.censys_certs.search(f"parsed.names: {domain}", per_page=5))
            return {"certificates": [c.get("parsed", {}) for c in certs]}
        except Exception as e:
            logger.error(f"Domain enrichment failed: {e}")
            return None

    def enrich_certificate(self, fingerprint):
        """
        Enriches a certificate using Censys Certificates API.
        """
        try:
            cert = self.censys_certs.view(fingerprint)
            return {
                "subject": cert.get("parsed", {}).get("subject", {}),
                "issuer": cert.get("parsed", {}).get("issuer", {}),
                "validity": cert.get("parsed", {}).get("validity", {})
            }
        except Exception as e:
            logger.error(f"Certificate enrichment failed: {e}")
            return None


class CensysConnector:
    """
    Main connector class that integrates with OpenCTI and Censys.
    """

    def __init__(self):
        self.config = ConfigManager().get_config()
        self.helper = OpenCTIConnectorHelper(self.config)
        self.censys_client = CensysClient(self.config["censys_api_id"], self.config["censys_api_secret"])
        self.stix_manager = STIXManager(self.helper)

    def _process_observable(self, observable):
        entity_type = observable["entity_type"]
        value = observable["value"]
        result = None
        url = None

        if entity_type == "IPv4-Addr":
            result = self.censys_client.enrich_ip(value)
            url = f"https://search.censys.io/hosts/{value}"
        elif entity_type == "Domain-Name":
            result = self.censys_client.enrich_domain(value)
            url = f"https://search.censys.io/certificates?q={value}"
        elif entity_type == "X509-Certificate":
            sha256 = observable.get("hashes", {}).get("SHA-256")
            if sha256:
                result = self.censys_client.enrich_certificate(sha256)
                url = f"https://search.censys.io/certificates/{sha256}"

        if result and url:
            bundle = self.stix_manager.create_stix_bundle(observable, result, url)
            self.helper.send_stix2_bundle(bundle.serialize())
            return f"Enriched {observable['value']}"
        return None

    def _process_message(self, data):
        try:
            observable_id = data["entity_id"]
            observable = self.helper.api.stix_cyber_observable.read(id=observable_id)

            if not observable:
                self.helper.connector_logger.error("Observable not found")
                return None

            markings = observable.get("objectMarking", [])
            if not self.helper.check_max_tlp(markings, self.config["max_tlp"]):
                self.helper.connector_logger.warning("Skipping due to TLP restrictions")
                return None

            return self._process_observable(observable)
        except Exception as e:
            self.helper.connector_logger.error(str(e))
            return None

    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        logger.info("Starting Censys connector...")
        connector = CensysConnector()
        connector.start()
    except Exception as e:
        logger.critical(f"Connector failed: {e}")
        exit(1)