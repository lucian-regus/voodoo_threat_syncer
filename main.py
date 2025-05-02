from config import load_config
from database.database_utils import ensure_target_database_exists, ensure_database_schema_initialized, update_threat_database

def main():
    load_config()

    ensure_target_database_exists()
    ensure_database_schema_initialized()

    update_threat_database()

if __name__ == '__main__':
    main()