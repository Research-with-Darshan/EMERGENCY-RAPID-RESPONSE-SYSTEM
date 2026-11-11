import hashlib
import hmac
import secrets
from .database import get_db
from .security import audit

def register_validator(validator_id, public_key, authorised=False):
    if not authorised:
        return {"accepted":False,"reason":"Authorised membership approval is required."}
    if not validator_id or not public_key:
        return {"accepted":False,"reason":"Validator ID and key are required."}
    db = get_db()
    existing = db.execute("SELECT * FROM validators WHERE validator_id=?", (validator_id,)).fetchone()
    if existing and existing["status"] == "ACTIVE":
        return {"accepted":False,"reason":"Validator is already active."}
    version = (existing["key_version"] + 1) if existing else 1
    if existing:
        db.execute("UPDATE validators SET public_key=?,key_version=?,status='ACTIVE',revoked_at=NULL WHERE id=?",
                   (public_key,version,existing["id"]))
    else:
        db.execute("INSERT INTO validators(validator_id,public_key,key_version,status) VALUES(?,?,?,'ACTIVE')",
                   (validator_id,public_key,version))
    db.commit()
    audit("VALIDATOR_REGISTERED","validator",validator_id,"SUCCESS",f"Key version {version}")
    return {"accepted":True,"validator_id":validator_id,"key_version":version}

def revoke_validator(validator_id, authorised=False):
    if not authorised:
        return {"revoked":False,"reason":"Authorised membership approval is required."}
    db = get_db()
    row = db.execute("SELECT * FROM validators WHERE validator_id=?", (validator_id,)).fetchone()
    if not row or row["status"] != "ACTIVE":
        return {"revoked":False,"reason":"No active validator exists with that ID."}
    db.execute("UPDATE validators SET status='REVOKED',revoked_at=CURRENT_TIMESTAMP WHERE id=?", (row["id"],))
    db.commit()
    audit("VALIDATOR_REVOKED","validator",validator_id,"SUCCESS",f"Revoked key version {row['key_version']}")
    return {"revoked":True,"validator_id":validator_id,"key_version":row["key_version"]}

def authenticate_validator(validator_id, key_version, message, signature):
    row = get_db().execute("SELECT * FROM validators WHERE validator_id=?", (validator_id,)).fetchone()
    if not row or row["status"] != "ACTIVE":
        return {"accepted":False,"reason":"Unknown, disabled or revoked validator."}
    if row["key_version"] != key_version:
        return {"accepted":False,"reason":"Outdated key version."}
    # HMAC is deliberately labelled as a symmetric teaching substitute, not a public-key signature.
    expected = hmac.new(bytes.fromhex(row["public_key"]), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return {"accepted":False,"reason":"Message authentication failed."}
    return {"accepted":True,"validator_id":validator_id,"key_version":key_version}
