import hashlib, hmac, json, secrets, uuid
from flask import has_request_context, session
from .database import get_db

ROLES = ["DISPATCHER","POLICE","PARAMEDIC","FIRE","INTELLIGENCE_ANALYST",
         "REGIONAL_COMMANDER","NATIONAL_COMMANDER","AUDITOR"]
LEVELS = {"PUBLIC": 0, "OPERATIONAL": 1, "SENSITIVE": 2, "RESTRICTED": 3}
ROLE_CLEARANCE = {
    "DISPATCHER": 1, "POLICE": 1, "PARAMEDIC": 1, "FIRE": 1,
    "INTELLIGENCE_ANALYST": 3, "REGIONAL_COMMANDER": 3,
    "NATIONAL_COMMANDER": 3, "AUDITOR": 3
}
# Explicit permissions; auditor is read-only for audit evidence.
PERMISSIONS = {
    "DISPATCHER": {"incident:read","incident:update","incident:verify","incident:reject",
                   "incident:request_info","service:create","resource:allocate","audit:read"},
    "POLICE": {"service:read:POLICE","service:respond:POLICE"},
    "PARAMEDIC": {"service:read:AMBULANCE","service:respond:AMBULANCE"},
    "FIRE": {"service:read:FIRE","service:respond:FIRE"},
    "INTELLIGENCE_ANALYST": {"intelligence:read","intelligence:update"},
    "REGIONAL_COMMANDER": {"region:read","region:escalate","incident:read"},
    "NATIONAL_COMMANDER": {"national:read","national:escalate","incident:read"},
    "AUDITOR": {"audit:read","policy:read","experiments:read","governance:read"},
}
def password_hash(password):
    try:
        from argon2 import PasswordHasher
        return "argon2$" + PasswordHasher().hash(password)
    except ImportError:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300000)
        return "pbkdf2$" + salt.hex() + "$" + digest.hex()

def verify_password(stored, password):
    if stored.startswith("argon2$"):
        try:
            from argon2 import PasswordHasher
            return PasswordHasher().verify(stored[7:], password)
        except Exception:
            return False
    if stored.startswith("pbkdf2$"):
        try:
            _, salt_hex, digest_hex = stored.split("$", 2)
            candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 300000).hex()
            return hmac.compare_digest(digest_hex, candidate)
        except (ValueError, TypeError):
            return False
    return False

def current_user():
    if not has_request_context() or "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=? AND status='ACTIVE'", (session["user_id"],)).fetchone()

def has_permission(user, permission):
    return bool(user and permission in PERMISSIONS.get(user["role"], set()))

def operation_kind(action):
    """Treat explicit reads as reads. Other authorised actions are writes."""
    markers = (":read", "read:")
    if any(marker in action for marker in markers) or action.endswith(":read"):
        return "read"
    return "write"

def bell_lapadula(user_level, resource_level, kind):
    # No read up: clearance must dominate the object's classification.
    # No write down: a subject may write only at or above its own clearance.
    if kind == "read":
        return user_level >= resource_level
    return user_level <= resource_level

def biba(user_level, integrity_level, kind):
    # Strict integrity. No read down, and no write up.
    if kind == "read":
        return user_level <= integrity_level
    return user_level >= integrity_level

def evaluate_policy(user, action, resource_class="OPERATIONAL", integrity="OPERATIONAL",
                    region_id=None, assigned_region_id=None, purpose="OPERATIONS"):
    """Combined ACM + Bell-LaPadula + Biba + contextual policy.

    Levels are ordered PUBLIC < OPERATIONAL < SENSITIVE < RESTRICTED.
    The same number is used as the subject's clearance and integrity level.
    Read and write are checked separately.
    """
    role = user["role"] if user else "ANONYMOUS"
    kind = operation_kind(action)
    allowed = has_permission(user, action)
    user_level = ROLE_CLEARANCE.get(role, 0)
    resource_level = LEVELS.get(resource_class, 3)
    integrity_level = LEVELS.get(integrity, 3)
    checks = {
        "ACM": allowed,
        "BELL_LAPADULA": bell_lapadula(user_level, resource_level, kind),
        "BIBA": biba(user_level, integrity_level, kind),
        "CONTEXT": bool(user and user["status"] == "ACTIVE" and purpose == "OPERATIONS"
                        and (region_id is None or assigned_region_id is None
                             or role in ("NATIONAL_COMMANDER","AUDITOR")
                             or region_id == assigned_region_id))
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {"decision":"PERMIT" if not failed else "DENY", "checks":checks,
            "failed_rules":failed, "operation":kind,
            "explanation":"All mandatory checks passed." if not failed
            else "Access denied because " + ", ".join(failed) + " did not permit the " + kind + " request.",
            "user":role, "action":action, "resource_class":resource_class}

def audit(action, object_type, object_id=None, outcome="SUCCESS", reason=""):
    db = get_db()
    user = current_user()
    previous = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous["event_hash"] if previous else "GENESIS"
    correlation = str(uuid.uuid4())
    payload = {"actor": user["id"] if user else None, "role": user["role"] if user else "PUBLIC",
               "action":action,"object_type":object_type,"object_id":str(object_id or ""),
               "outcome":outcome,"reason":reason,"correlation_id":correlation,
               "previous_hash":previous_hash}
    event_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    db.execute("""INSERT INTO audit_events(actor_id,actor_role,action,object_type,object_id,
               outcome,reason,correlation_id,previous_hash,event_hash)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (payload["actor"],payload["role"],action,object_type,payload["object_id"],
                outcome,reason,correlation,previous_hash,event_hash))
    db.commit()

def verify_audit_chain():
    rows = get_db().execute("SELECT * FROM audit_events ORDER BY id").fetchall()
    previous = "GENESIS"
    for row in rows:
        payload = {"actor":row["actor_id"],"role":row["actor_role"],"action":row["action"],
                   "object_type":row["object_type"],"object_id":row["object_id"],
                   "outcome":row["outcome"],"reason":row["reason"],
                   "correlation_id":row["correlation_id"],"previous_hash":previous}
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(row["event_hash"], expected):
            return False
        previous = row["event_hash"]
    return True

def seal_checkpoint():
    """Store a signed head of the audit chain outside the database file."""
    from flask import current_app
    from pathlib import Path
    if not verify_audit_chain():
        return {"sealed": False, "reason": "Audit chain failed verification."}
    db = get_db()
    rows = db.execute("SELECT event_hash FROM audit_events ORDER BY id").fetchall()
    head = rows[-1]["event_hash"] if rows else "GENESIS"
    payload = f"{len(rows)}:{head}"
    signature = hmac.new(current_app.config["SECRET_KEY"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    db.execute("""CREATE TABLE IF NOT EXISTS audit_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_count INTEGER NOT NULL,
        head_hash TEXT NOT NULL, signature TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    db.execute("INSERT INTO audit_checkpoints(event_count,head_hash,signature) VALUES(?,?,?)",
               (len(rows), head, signature))
    db.commit()
    folder = Path(current_app.root_path).parent / "evidence" / "checkpoints"
    folder.mkdir(parents=True, exist_ok=True)
    record = {"event_count": len(rows), "head_hash": head, "signature": signature}
    (folder / "latest.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return {"sealed": True, **record}

def verify_checkpoint():
    from flask import current_app
    from pathlib import Path
    if not verify_audit_chain():
        return False
    path = Path(current_app.root_path).parent / "evidence" / "checkpoints" / "latest.json"
    if not path.exists():
        return True
    saved = json.loads(path.read_text(encoding="utf-8"))
    rows = get_db().execute("SELECT event_hash FROM audit_events ORDER BY id").fetchall()
    head = rows[-1]["event_hash"] if rows else "GENESIS"
    payload = f"{len(rows)}:{head}"
    expected = hmac.new(current_app.config["SECRET_KEY"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    return saved.get("event_count") == len(rows) and saved.get("head_hash") == head and hmac.compare_digest(saved.get("signature", ""), expected)

def make_report_token():
    return secrets.token_urlsafe(32)
def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()
