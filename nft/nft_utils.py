from config import NFT_CHAIN_NAME, NFT_TABLE_NAME, NFT_SET_NAME, NFT_FILE_PATH
import subprocess
from logger_config import logger

def fetch_blacklisted_ips(cursor):
    cursor.execute('SELECT ip_address FROM blacklisted_ip_addresses WHERE allowed_at IS NULL;')
    ips = [row[0] for row in cursor.fetchall()]

    return ips

def generate_nft_file(ips):
    with open(NFT_FILE_PATH, "w") as file:
        file.write(f"table inet {NFT_TABLE_NAME} {{")
        file.write(f"\tset {NFT_SET_NAME} {{\n")
        file.write("\t\ttype ipv4_addr;\n")
        file.write("\t\tflags interval;\n")

        if ips:
            file.write("\t\telements = {\n")
            for i, ip in enumerate(ips):
                comma = "," if i < len(ips) - 1 else ""
                file.write(f"\t\t\t{ip}{comma}\n")
            file.write("\t\t};\n")
        else:
            file.write("\t\telements = { };\n")

        file.write("\t}\n\n")
        file.write(f"\tchain {NFT_CHAIN_NAME} {{\n")
        file.write("\t\ttype filter hook output priority 0; policy accept;\n")
        file.write(f"\t\tip daddr @{NFT_SET_NAME} drop\n")
        file.write("\t}\n")
        file.write("}\n")

def update_nft_ruleset(cursor):
    ips = fetch_blacklisted_ips(cursor)
    generate_nft_file(ips)

    subprocess.run(["nft", "flush", "ruleset"])
    subprocess.run(["nft", "-f", NFT_FILE_PATH])

    logger.info("NFT Ruleset updated")