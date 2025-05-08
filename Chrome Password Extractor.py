import os
import sqlite3
import win32crypt
from datetime import datetime
import csv
import json
import logging

# Setup logging
logging.basicConfig(
    filename="credential_manager.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
DATA_PATH = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\Login Data"
BACKUP_PATH = "Login_Data_Backup.db"
TEXT_OUTPUT = "chrome_passwords.txt"
CSV_OUTPUT = "chrome_passwords.csv"
JSON_OUTPUT = "chrome_passwords.json"

# Database Operations

def fetch_chrome_credentials(db_path):
    """Connects to Chrome login data DB and retrieves credentials."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        results = cursor.fetchall()
    logging.info("Fetched Chrome credentials from database.")
    return results


def store_or_update_credential(db_path, url, username, plain_password):
    """Inserts or updates a credential entry."""
    try:
        encrypted_password = encrypt_password(plain_password)[1]
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM logins WHERE action_url = ? AND username_value = ?', (url, username))
            if cursor.fetchone()[0]:
                cursor.execute(
                    'UPDATE logins SET password_value = ? WHERE action_url = ? AND username_value = ?',
                    (encrypted_password, url, username)
                )
                logging.info(f"Updated credential for {username} at {url}.")
                print("Credential updated successfully.")
            else:
                cursor.execute(
                    'INSERT INTO logins (origin_url, action_url, username_value, password_value) VALUES (?, ?, ?, ?)',
                    (url, url, username, encrypted_password)
                )
                logging.info(f"Added new credential for {username} at {url}.")
                print("Credential added successfully.")
            conn.commit()
    except Exception as e:
        logging.error(f"Error storing/updating credential: {e}")
        print(f"Error: {e}")

# Encryption Helpers

def encrypt_password(plain_password):
    try:
        return win32crypt.CryptProtectData(plain_password.encode(), None, None, None, None, 0)
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return f"Error encrypting password: {e}"


def decrypt_password(encrypted_password):
    try:
        return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return f"Error decrypting password: {e}"

# Display Functions

def display_credentials(credentials):
    for site, username, encrypted_password in credentials:
        password = decrypt_password(encrypted_password)
        print(f"Website : {site}\nUsername : {username}\nPassword : {password}\n{'-'*50}")

# Export Functions

def save_credentials_to_file(credentials, filename=TEXT_OUTPUT):
    with open(filename, "w", encoding="utf-8") as file:
        for site, username, encrypted_password in credentials:
            password = decrypt_password(encrypted_password)
            file.write(f"Website : {site}\nUsername : {username}\nPassword : {password}\n{'-'*50}\n")
    logging.info(f"Credentials written to text file: {filename}")


def export_credentials_to_csv(credentials, filename=CSV_OUTPUT):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Website", "Username", "Password"])
        for site, username, encrypted_password in credentials:
            password = decrypt_password(encrypted_password)
            writer.writerow([site, username, password])
    logging.info(f"Credentials exported to CSV: {filename}")


def export_credentials_to_json(credentials, filename=JSON_OUTPUT):
    export_data = [
        {"Website": site, "Username": username, "Password": decrypt_password(encrypted_password)}
        for site, username, encrypted_password in credentials
    ]
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(export_data, file, indent=4)
    logging.info(f"Credentials exported to JSON: {filename}")

# Utility Functions

def count_total_credentials(credentials):
    return len(credentials)

def filter_credentials_by_domain(credentials, domain):
    return [cred for cred in credentials if domain in cred[0]]

def search_credentials_by_username(credentials, keyword):
    return [cred for cred in credentials if keyword.lower() in cred[1].lower()]

def get_unique_domains(credentials):
    return list(set(cred[0] for cred in credentials))

def redact_sensitive_data(credentials):
    return [(site, username, "[REDACTED]") for site, username, _ in credentials]

# Backup and File Info

def backup_login_data(db_path, backup_path=BACKUP_PATH):
    try:
        if os.path.exists(db_path):
            with open(db_path, 'rb') as original, open(backup_path, 'wb') as backup:
                backup.write(original.read())
            logging.info(f"Backup created at {backup_path}")
            print(f"Backup created at {backup_path}")
        else:
            logging.warning("Login Data file not found.")
    except Exception as e:
        logging.error(f"Backup failed: {e}")


def get_last_modified_time(db_path):
    return datetime.fromtimestamp(os.path.getmtime(db_path)).strftime("%Y-%m-%d %H:%M:%S") if os.path.exists(db_path) else "File not found."

# Main Function

def main():
    if not os.path.exists(DATA_PATH):
        print("Login Data file not found.")
        logging.error("Login Data file not found.")
        return

    print(f"Login Data last modified: {get_last_modified_time(DATA_PATH)}")
    backup_login_data(DATA_PATH)

    credentials = fetch_chrome_credentials(DATA_PATH)
    display_credentials(credentials)

    save_credentials_to_file(credentials)
    export_credentials_to_csv(credentials)
    export_credentials_to_json(credentials)

    print(f"Total credentials: {count_total_credentials(credentials)}")

    filtered = filter_credentials_by_domain(credentials, "google.com")
    print("\nFiltered by domain 'google.com':")
    display_credentials(filtered)

    searched = search_credentials_by_username(credentials, "user")
    print("\nFiltered by username 'user':")
    display_credentials(searched)

    print("\nUnique domains:")
    for domain in get_unique_domains(credentials):
        print(domain)

    print("\nRedacted credentials:")
    display_credentials(redact_sensitive_data(credentials))

    # Uncomment to test storing/updating credentials
    # store_or_update_credential(DATA_PATH, "https://example.com", "sample_user", "sample_pass")

if __name__ == "__main__":
    main()
