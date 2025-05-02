from logger_config import logger
from config import TEMP_YAR_FILE, COMPILED_YARAC_FILE
import subprocess

def fetch_yara_rules(cursor):
    cursor.execute("SELECT id, rule FROM yara_rules;")
    rules = cursor.fetchall()

    return rules

def update_yara_ruleset(cursor):
    rules = fetch_yara_rules(cursor)

    with open(TEMP_YAR_FILE, "w") as f:
        for rule_id, rule_body in rules:
            full_rule = f"rule rule_{rule_id} {{\n{rule_body.strip()}\n}}\n\n"
            f.write(full_rule)

    subprocess.run(["yarac", TEMP_YAR_FILE, COMPILED_YARAC_FILE], check=True)

    logger.info("Yara Ruleset updated")