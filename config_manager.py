import os  # Add this import at the top of your script

class ConfigConnector:
    """
    Handles loading and validating the connector configuration from environment variables.
    """

    def __init__(self):
        # Define required configuration keys and their corresponding environment variables
        required_keys = {
            "censys_api_id": "CENSYS_API_ID",
            "censys_api_secret": "CENSYS_API_SECRET",
            "opencti_url": "OPENCTI_URL",
            "opencti_token": "OPENCTI_TOKEN",
            "connector_id": "CONNECTOR_ID"
        }

        self.config = {}

        # Validate that all required environment variables are set
        for key, env_var in required_keys.items():
            value = os.getenv(env_var)
            if not value:
                logger.critical(f"Missing required environment variable: {env_var}")
                exit(1)
            self.config[key] = value

        # Set default values for optional configuration parameters
        self.config.setdefault("connector_scope", ["IPv4-Addr", "Domain-Name", "X509-Certificate"])
        self.config.setdefault("max_tlp", "TLP:AMBER")

    @property
    def load(self):
        """
        Returns the loaded configuration.
        """
        return self.config
