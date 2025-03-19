import yaml
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Handles loading and validating configuration from a YAML file.
    """

    def __init__(self, config_file="config.yml"):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """
        Loads and validates the configuration from the YAML file.
        """
        try:
            with open(self.config_file, "r") as file:
                config = yaml.safe_load(file)

            # Define required configuration keys
            required_keys = [
                "censys_api_id", "censys_api_secret",
                "opencti_url", "opencti_token", "connector_id"
            ]

            # Validate that all required keys are present
            for key in required_keys:
                if key not in config:
                    logger.critical(f"Missing required configuration key: {key}")
                    exit(1)

            # Set default values for optional configuration parameters
            config.setdefault("connector_scope", ["IPv4-Addr", "Domain-Name", "X509-Certificate"])
            config.setdefault("max_tlp", "TLP:AMBER")

            return config

        except FileNotFoundError:
            logger.critical(f"Configuration file '{self.config_file}' not found. Exiting...")
            exit(1)
        except yaml.YAMLError as e:
            logger.critical(f"Error parsing configuration file: {e}")
            exit(1)

    def get_config(self):
        """
        Returns the loaded configuration.
        """
        return self.config