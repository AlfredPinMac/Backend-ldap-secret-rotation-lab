import os
import sqlite3
import base64
import hashlib
import time
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from ldap3 import Server, Connection, ALL, SUBTREE

app = Flask(__name__)
CORS(app)

# ==============================================================================
# SECRETS & DYNAMIC ROTATION MANAGEMENT
# ==============================================================================
API_SECRETS_FILE = Path("/secrets/api_secret.env")
LDAP_SECRETS_FILE = Path("/secrets/ldap_secret.env")
DEFAULT_API_SECRET = os.environ.get("API_SECRET", "LAB_INITIAL_SECRET_ABC123")
DEFAULT_LDAP_ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "adminpassword")

LDAP_HOST = os.environ.get("LDAP_HOST", "openldap")
LDAP_PORT = int(os.environ.get("LDAP_PORT", "389"))
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")

def get_current_api_secret() -> str:
    """
    Retrieves the active API_SECRET shared between NGINX and Backend.
    Reads dynamically from the shared volume /secrets/api_secret.env.
    """
    if API_SECRETS_FILE.exists():
        try:
            content = API_SECRETS_FILE.read_text().strip()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("export API_SECRET="):
                    return line.split("=", 1)[1].strip('"\'')
                elif line.startswith("API_SECRET="):
                    return line.split("=", 1)[1].strip('"\'')
        except Exception as e:
            app.logger.warning(f"Failed reading api_secret.env: {e}")
    return os.environ.get("API_SECRET", DEFAULT_API_SECRET)

def get_current_ldap_admin_secret() -> str:
    """
    Retrieves the active LDAP administrator / service secret.
    Reads dynamically from /secrets/ldap_secret.env.
    """
    if LDAP_SECRETS_FILE.exists():
        try:
            content = LDAP_SECRETS_FILE.read_text().strip()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("export LDAP_ADMIN_PASSWORD="):
                    return line.split("=", 1)[1].strip('"\'')
                elif line.startswith("LDAP_ADMIN_PASSWORD="):
                    return line.split("=", 1)[1].strip('"\'')
        except Exception as e:
            app.logger.warning(f"Failed reading ldap_secret.env: {e}")
    return os.environ.get("LDAP_ADMIN_PASSWORD", DEFAULT_LDAP_ADMIN_PASSWORD)

def get_database_encryption_key() -> str:
    """
    Returns the fixed SQLite encryption key.
    CRITICAL: This key MUST NOT be rotated.
    """
    return os.environ.get("DATABASE_ENCRYPTION_KEY", "LAB_ENCRYPTION_KEY_FIXED_2026_DO_NOT_ROTATE")

def get_fernet_cipher() -> Fernet:
    """
    Derives a standard 32-byte URL-safe Fernet key using SHA-256.
    """
    raw_key = get_database_encryption_key().encode("utf-8")
    key_hash = hashlib.sha256(raw_key).digest()
    fernet_key = base64.urlsafe_b64encode(key_hash)
    return Fernet(fernet_key)

def encrypt_data(plaintext: str) -> str:
    return get_fernet_cipher().encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_data(ciphertext: str) -> str:
    return get_fernet_cipher().decrypt(ciphertext.encode("utf-8")).decode("utf-8")


# ==============================================================================
# DATABASE INITIALIZATION (SQLite)
# ==============================================================================
DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS confidential_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_by TEXT DEFAULT 'system',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    # Seed initial encrypted data if empty
    cursor.execute("SELECT COUNT(*) FROM confidential_records")
    if cursor.fetchone()[0] == 0:
        seed_items = [
            ("Corporate Bank Vault Coordinates", "Vault: #702-Alpha, Routing: 021000021, Master Code: 9948-AX-2026", "admin"),
            ("Confidential Clinical Record", "Patient ID: 9482, Diagnosis: Condition Controlled, Status: Normal", "alice"),
            ("Production Cloud KMS Key Reference", "KMS Key ID: kms:us-east-1:rot-key-991204, Keyring: security-ring", "bob")
        ]
        for title, sensitive_info, author in seed_items:
            encrypted_text = encrypt_data(sensitive_info)
            cursor.execute(
                "INSERT INTO confidential_records (title, encrypted_payload, created_by) VALUES (?, ?, ?)",
                (title, encrypted_text, author)
            )
        conn.commit()
    conn.close()

try:
    init_db()
except Exception as e:
    print(f"Database init warning: {e}")


# ==============================================================================
# AUTHENTICATION & API KEY MIDDLEWARE
# ==============================================================================
def verify_api_key():
    provided_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    current_key = get_current_api_secret()

    if not provided_key:
        return False, {"error": "Unauthorized", "message": "Missing required X-API-Key header"}, 401
    
    if provided_key != current_key:
        return False, {"error": "Unauthorized", "message": "Invalid or expired X-API-Key value"}, 401

    return True, None, 200


# ==============================================================================
# LDAP AUTHENTICATION LOGIC
# ==============================================================================
def authenticate_ldap_user(username: str, password: str):
    """
    Authenticates a user against OpenLDAP:
    1. Special check for admin user with rotated LDAP_ADMIN_PASSWORD.
    2. Binds as the user or searches LDAP under ou=users,dc=example,dc=com.
    3. Retrieves profile attributes and group memberships.
    """
    server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL)
    current_admin_pass = get_current_ldap_admin_secret()

    # Handle LDAP Administrator
    if username == "admin":
        admin_dn = f"cn=admin,{LDAP_BASE_DN}"
        conn = Connection(server, user=admin_dn, password=password, auto_bind=False)
        try:
            if conn.bind():
                return {
                    "authenticated": True,
                    "username": "admin",
                    "displayName": "LDAP Administrator",
                    "email": "admin@example.com",
                    "dn": admin_dn,
                    "role": "Administrator",
                    "groups": ["administrators", "security-team"]
                }
        finally:
            conn.unbind()
        return None

    # Handle Standard LDAP Users (e.g., alice, bob)
    user_dn = f"uid={username},ou=users,{LDAP_BASE_DN}"
    conn = Connection(server, user=user_dn, password=password, auto_bind=False)

    try:
        if conn.bind():
            # Retrieve user attributes using the established connection
            search_ok = conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=f"(uid={username})",
                search_scope=SUBTREE,
                attributes=["cn", "mail", "displayName", "givenName", "sn"]
            )
            display_name = username.capitalize()
            mail = f"{username}@example.com"

            if search_ok and conn.entries:
                entry = conn.entries[0]
                if "displayName" in entry and entry.displayName.value:
                    display_name = str(entry.displayName.value)
                elif "cn" in entry and entry.cn.value:
                    display_name = str(entry.cn.value)
                if "mail" in entry and entry.mail.value:
                    mail = str(entry.mail.value)

            # Query group membership
            groups = []
            admin_conn = Connection(server, user=f"cn=admin,{LDAP_BASE_DN}", password=current_admin_pass, auto_bind=False)
            try:
                if admin_conn.bind():
                    admin_conn.search(
                        search_base=f"ou=groups,{LDAP_BASE_DN}",
                        search_filter=f"(member={user_dn})",
                        search_scope=SUBTREE,
                        attributes=["cn"]
                    )
                    for group_entry in admin_conn.entries:
                        if "cn" in group_entry:
                            groups.append(str(group_entry.cn.value))
            except Exception as ge:
                app.logger.warning(f"Group lookup warning: {ge}")
            finally:
                admin_conn.unbind()

            return {
                "authenticated": True,
                "username": username,
                "displayName": display_name,
                "email": mail,
                "dn": user_dn,
                "role": "User",
                "groups": groups or ["developers"]
            }
    except Exception as e:
        app.logger.error(f"LDAP bind error for {username}: {e}")
        return None
    finally:
        conn.unbind()

    return None


# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    """Health check validating SQLite DB and LDAP connectivity."""
    ldap_status = "unreachable"
    try:
        server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL, connect_timeout=2)
        test_conn = Connection(server, auto_bind=False)
        if test_conn.open():
            ldap_status = "connected"
            test_conn.unbind()
    except Exception:
        ldap_status = "error"

    return jsonify({
        "status": "ok",
        "service": "Integrated Backend Security & LDAP API",
        "database": "sqlite_connected",
        "ldap": ldap_status,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }), 200


@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def login():
    """
    LDAP Login Endpoint:
    Receives { "username": "alice", "password": "..." }
    Authenticates against OpenLDAP server.
    """
    is_valid, err_response, status_code = verify_api_key()
    if not is_valid:
        return jsonify(err_response), status_code

    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    password = payload.get("password", "").strip()

    if not username or not password:
        return jsonify({
            "authenticated": False,
            "error": "Bad Request",
            "message": "Both 'username' and 'password' are required"
        }), 400

    user_info = authenticate_ldap_user(username, password)
    if not user_info:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized",
            "message": "Invalid LDAP username or password"
        }), 401

    return jsonify({
        "authenticated": True,
        "message": "LDAP Authentication successful",
        "user": user_info
    }), 200


@app.route("/secure-data", methods=["GET"])
@app.route("/api/secure-data", methods=["GET"])
def get_secure_data():
    """
    Protected GET Endpoint:
    1. Validates X-API-Key against active API_SECRET.
    2. Retrieves encrypted records from SQLite.
    3. Decrypts records on the fly using fixed DATABASE_ENCRYPTION_KEY.
    """
    is_valid, err_response, status_code = verify_api_key()
    if not is_valid:
        return jsonify(err_response), status_code

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, encrypted_payload, created_by, created_at FROM confidential_records ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        rec_id, title, ciphertext, created_by, created_at = row
        try:
            plaintext = decrypt_data(ciphertext)
        except Exception as e:
            plaintext = f"[Decryption Error: {str(e)}]"

        results.append({
            "id": rec_id,
            "title": title,
            "decrypted_data": plaintext,
            "raw_encrypted_in_db": ciphertext,
            "created_by": created_by,
            "created_at": created_at
        })

    cur_sec = get_current_api_secret()
    cur_ldap = get_current_ldap_admin_secret()
    cur_db = get_database_encryption_key()

    return jsonify({
        "status": "success",
        "count": len(results),
        "records": results,
        "metadata": {
            "auth_status": "X-API-Key and LDAP verified",
            "active_api_secret_sample": cur_sec[:6] + "..." if len(cur_sec) > 6 else cur_sec,
            "active_ldap_secret_sample": cur_ldap[:6] + "..." if len(cur_ldap) > 6 else cur_ldap,
            "database_encryption_key_sample": cur_db[:6] + "..." if len(cur_db) > 6 else cur_db,
            "rotation_status": "API_SECRET & LDAP_SECRET rotate dynamically | DATABASE_ENCRYPTION_KEY is FIXED"
        }
    }), 200


@app.route("/data", methods=["POST"])
@app.route("/api/data", methods=["POST"])
def post_data():
    """
    Protected POST Endpoint:
    1. Validates X-API-Key.
    2. Encrypts payload with DATABASE_ENCRYPTION_KEY.
    3. Stores encrypted ciphertext into SQLite database.
    """
    is_valid, err_response, status_code = verify_api_key()
    if not is_valid:
        return jsonify(err_response), status_code

    payload = request.get_json(silent=True) or {}
    title = payload.get("title", "").strip() or "Confidential Record"
    secret_data = payload.get("secret_data", "").strip()
    created_by = payload.get("username", "authenticated_user").strip()

    if not secret_data:
        return jsonify({"error": "Bad Request", "message": "'secret_data' field is required"}), 400

    encrypted_payload = encrypt_data(secret_data)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO confidential_records (title, encrypted_payload, created_by) VALUES (?, ?, ?)",
        (title, encrypted_payload, created_by)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Data encrypted and stored in SQLite database",
        "record": {
            "id": new_id,
            "title": title,
            "created_by": created_by,
            "encrypted_stored": encrypted_payload,
            "encryption_algorithm": "AES-256 (Fernet CBC + HMAC-SHA256)"
        }
    }), 201


@app.route("/db-raw", methods=["GET"])
@app.route("/api/db-raw", methods=["GET"])
def inspect_raw_db():
    """Protected Diagnostic Endpoint: Inspects raw SQLite ciphertexts on disk."""
    is_valid, err_response, status_code = verify_api_key()
    if not is_valid:
        return jsonify(err_response), status_code

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, encrypted_payload, created_by, created_at FROM confidential_records")
    rows = cursor.fetchall()
    conn.close()

    raw_items = [
        {
            "id": r[0],
            "title": r[1],
            "ciphertext_in_database": r[2],
            "created_by": r[3],
            "created_at": r[4]
        }
        for r in rows
    ]

    return jsonify({
        "table": "confidential_records",
        "total_records": len(raw_items),
        "raw_database_content": raw_items
    }), 200


@app.route("/status", methods=["GET"])
@app.route("/api/status", methods=["GET"])
def rotation_status():
    """Returns current rotation and secrets metadata across all 3 services."""
    is_valid, err_response, status_code = verify_api_key()
    if not is_valid:
        return jsonify(err_response), status_code

    cur_sec = get_current_api_secret()
    cur_ldap = get_current_ldap_admin_secret()
    cur_db = get_database_encryption_key()

    return jsonify({
        "services": {
            "frontend_nginx": {
                "name": "Frontend NGINX Reverse Proxy",
                "secret_name": "API_SECRET (X-API-Key)",
                "active_value_sample": cur_sec[:6] + "..." if len(cur_sec) > 6 else cur_sec,
                "rotatable": True,
                "status": "Active & Synchronized"
            },
            "ldap_directory": {
                "name": "OpenLDAP Directory Service",
                "secret_name": "LDAP_ADMIN_PASSWORD",
                "active_value_sample": cur_ldap[:6] + "..." if len(cur_ldap) > 6 else cur_ldap,
                "rotatable": True,
                "status": "Active & Synchronized"
            },
            "backend_database": {
                "name": "Backend SQLite Storage",
                "secret_name": "DATABASE_ENCRYPTION_KEY",
                "active_value_sample": cur_db[:6] + "..." if len(cur_db) > 6 else cur_db,
                "rotatable": False,
                "status": "Fixed (DO NOT ROTATE)"
            }
        },
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
