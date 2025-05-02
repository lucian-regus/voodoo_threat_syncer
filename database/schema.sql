CREATE TABLE IF NOT EXISTS blacklisted_ip_addresses (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(39) UNIQUE NOT NULL,
    allowed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS malware_signatures (
    id SERIAL PRIMARY KEY,
    signature VARCHAR(512) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id SERIAL PRIMARY KEY,
    rule VARCHAR(2500) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS database_update_log (
    id SERIAL PRIMARY KEY,
    last_update TIMESTAMP UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS malware_detection_log (
    id SERIAL PRIMARY KEY,
    file_identity TEXT NOT NULL,
    original_path TEXT NOT NULL,
    old_name TEXT NOT NULL,
    new_name TEXT NOT NULL,
    detected_by TEXT NOT NULL,
    detected_by_id INT NOT NULL,
    detected_at TIMESTAMP DEFAULT now(),
    allowed_at TIMESTAMP
);
