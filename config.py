import os
from dotenv import load_dotenv

load_dotenv()

SOCKET_PATH = "/tmp/voodoo.sock"

# Logging
LOG_DIR = "/var/log/voodoo"
LOG_FILE = os.path.join(LOG_DIR, "threat_sync.log")

# NFTables
NFT_FILE_PATH = "/var/lib/voodoo/blacklist.nft"
NFT_TABLE_NAME = "voodoo"
NFT_SET_NAME = "blocked_ips"
NFT_CHAIN_NAME = "drop_blacklisted_ips"

# Yara Rules
TEMP_YAR_FILE = "/var/lib/voodoo/temp_rules.yar"
COMPILED_YARAC_FILE = "/var/lib/voodoo/compiled_rules.yarac"

# .env config
TARGET_DATABASE_NAME = os.getenv("TARGET_DATABASE_NAME")
TARGET_API = os.getenv("TARGET_API")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

REQUIRED_ENV_VARS = [
    "TARGET_DATABASE_NAME",
    "TARGET_API",
    "DATABASE_USER",
    "DATABASE_PASSWORD"
]

def load_config():
    missing = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        raise EnvironmentError(
            f"[ERROR] Missing required environment variables: {', '.join(missing)}"
        )