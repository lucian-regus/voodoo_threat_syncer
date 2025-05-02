from psycopg2 import sql
from db_connection import get_db_connection
from config import TARGET_DATABASE_NAME, TARGET_API
from logger_config import logger
from time import sleep
from nft.nft_utils import update_nft_ruleset
from yara.yara_utils import update_yara_ruleset
import os
import requests

def filter_entries(entries, field, deleted=False):
    return [(entry[field],) for entry in entries if entry.get("wasRemoved") is deleted]

def fetch_last_update(cursor):
    cursor.execute("SELECT last_update FROM database_update_log ORDER BY last_update DESC LIMIT 1;")

    return cursor.fetchone()

def build_update_url(last_update):
    if last_update:
        delta = last_update[0].strftime('%Y-%m-%dT%H:%M:%S.%f')
        return f"http://{TARGET_API}/api/database/updates?delta={delta}"

    return f"http://{TARGET_API}/api/database/updates"

def execute_batch(cursor, query, entries):
    if entries:
        cursor.executemany(query, entries)

def ensure_target_database_exists():
    connection = get_db_connection('postgres')
    connection.autocommit = True
    cursor = connection.cursor()

    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (TARGET_DATABASE_NAME,))
    if not cursor.fetchone():
        logger.info("Database created")
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(TARGET_DATABASE_NAME)))

    cursor.close()
    connection.close()

def ensure_database_schema_initialized():
    connection = get_db_connection(TARGET_DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
                   SELECT EXISTS (
                       SELECT FROM information_schema.tables
                       WHERE table_schema = 'public'
                         AND table_name = 'malware_signatures'
                   );
                   """)
    schema_exists = cursor.fetchone()[0]

    if not schema_exists:
        logger.info("Schema created")
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, 'r') as file:
            schema_sql = file.read()

        cursor.execute(schema_sql)
        connection.commit()

    cursor.close()
    connection.close()

def sync_database_with_api_data(data, cursor, connection):
    signatures = data.get("malwareSignatures", [])
    yara_rules = data.get("yaraRules", [])
    blacklisted_ips = data.get("blacklistedIpAddresses", [])

    new_signatures = filter_entries(signatures, "signature")

    new_yara = filter_entries(yara_rules, "rule")

    new_ips = filter_entries(blacklisted_ips, "ipAddress")
    remove_ips = filter_entries(blacklisted_ips, "ipAddress", deleted=True)

    execute_batch(cursor, "DELETE FROM blacklisted_ip_addresses WHERE ip_address = %s;", remove_ips)

    execute_batch(cursor, "INSERT INTO malware_signatures (signature) VALUES (%s);", new_signatures)
    execute_batch(cursor, "INSERT INTO yara_rules (rule) VALUES (%s);", new_yara)
    execute_batch(cursor, "INSERT INTO blacklisted_ip_addresses (ip_address) VALUES (%s);", new_ips)

    if new_signatures or new_yara or new_ips or remove_ips:
        cursor.execute("INSERT INTO database_update_log (last_update) VALUES (CURRENT_TIMESTAMP);")
        connection.commit()

        logger.info(
            f"[+] Threat data committed – "
            f"Signatures: +{len(new_signatures)}, "
            f"YARA: +{len(new_yara)}, "
            f"IPs: +{len(new_ips)}/-{len(remove_ips)}"
        )

    if new_ips or remove_ips:
        update_nft_ruleset(cursor)

    if new_yara:
        update_yara_ruleset(cursor)

def update_threat_database():
    while True:
        logger.info("Update cycle started")
        connection = get_db_connection(TARGET_DATABASE_NAME)
        cursor = connection.cursor()

        try:
            update_url = build_update_url(fetch_last_update(cursor))
            response = requests.get(update_url)
            response.raise_for_status()

            data = response.json()
            sync_database_with_api_data(data, cursor, connection)

        except requests.RequestException:
            logger.error("Update cycle failed")
        except Exception as e:
            logger.exception(f"Unexpected error during update: {e}")
        finally:
            logger.info("Update cycle ended")
            cursor.close()
            connection.close()
            sleep(3600)