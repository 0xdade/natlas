import os
from dotenv import load_dotenv

NATLAS_VERSION = "0.6.12"


def get_int(varname: str, default: any = None):
    """
        Read string from environment and cast it to int
    """
    tmp = os.environ.get(varname)
    if tmp:
        return int(tmp)
    return default


def get_bool(varname: str, default: any = None):
    """
        Read string from environment and massage it to native boolean
        Cannot just bool(tmp) because bool("False") returns True
    """
    tmp = os.environ.get(varname)
    if tmp and tmp.upper() == "TRUE":
        return True
    if tmp and tmp.upper() == "FALSE":
        return False
    return default


class Config:
    class __Config:

        def __init__(self):

            # Current Version
            self.NATLAS_VERSION = NATLAS_VERSION

            # url of server to get/submit work from/to
            self.server = os.environ.get(
                "NATLAS_SERVER_ADDRESS", "http://127.0.0.1:5000"
            )

            # Location of data directory
            self.data_dir = os.environ.get("NATLAS_DATA_DIR", "/data")

            # ignore warnings about SSL connections
            # you shouldn't ignore ssl warnings, but I'll give you the option
            # Instead, you should put the trusted CA certificate bundle on the agent and use the REQUESTS_CA_BUNDLE env variable
            self.ignore_ssl_warn = get_bool("NATLAS_IGNORE_SSL_WARN", False)

            # maximum number of threads to utilize
            self.max_threads = get_int("NATLAS_MAX_THREADS", 3)

            # Are we allowed to scan local addresses?
            # By default, agents protect themselves from scanning their local network
            self.scan_local = get_bool("NATLAS_SCAN_LOCAL", False)

            # default time to wait for the server to respond
            self.request_timeout = get_int("NATLAS_REQUEST_TIMEOUT", 15)  # seconds

            # Maximum value for exponential backoff of requests, 5 minutes default
            self.backoff_max = get_int("NATLAS_BACKOFF_MAX", 300)  # seconds

            # Base value to begin the exponential backoff
            self.backoff_base = get_int("NATLAS_BACKOFF_BASE", 1)  # seconds

            # Maximum number of times to retry submitting data before giving up
            # This is useful if a thread is submitting data that the server doesn't understand for some reason
            self.max_retries = get_int("NATLAS_MAX_RETRIES", 10)

            # Identification string that identifies the agent that performed any given scan
            # Used for database lookup and stored in scan output
            self.agent_id = os.environ.get("NATLAS_AGENT_ID", None)

            # Authentication token that agents can use to talk to the server API
            # Only needed if the server is configured to require agent authentication
            self.auth_token = os.environ.get("NATLAS_AGENT_TOKEN", None)

            # Optionally save files that failed to upload
            self.save_fails = get_bool("NATLAS_SAVE_FAILS", False)

            # Allow version overrides for local development
            # Necessary to test versioned host data templates before release
            self.version_override = os.environ.get("NATLAS_VERSION_OVERRIDE", None)

            if self.version_override:
                self.NATLAS_VERSION = self.version_override

            # Optional Data source name for reporting exceptions to Sentry
            self.sentry_dsn = os.environ.get("SENTRY_DSN", None)

            # Logging level to use
            self.log_level = os.environ.get("NATLAS_LOG_LEVEL", "INFO").upper()

            # Optionally log to a file
            self.log_to_file = get_bool("NATLAS_LOG_TO_FILE", False)

    instance = None

    def __init__(self):
        """
            A singleton config. This pattern lets us access the same config object from other modules without
            needing to pass the instance around as a parameter. It makes the assumption that the running process
            should only have one configuration for it's lifetime.
        """
        if not Config.instance:
            Config.instance = Config.__Config()

    def __getattr__(self, name):
        return getattr(self.instance, name)
