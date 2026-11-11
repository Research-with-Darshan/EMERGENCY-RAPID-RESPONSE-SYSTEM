import json, re, uuid, hashlib, hmac, secrets
from datetime import datetime, timedelta
from pathlib import Path
from .security import LEVELS

def assess_incident(incident_type, description, injuries="", hazards="", people=None):
    text = " ".join([incident_type, description, injuries or "", hazards or ""]).lower()
    score = 1
    reasons = []
    urgent_terms = ["fire","explosion","trapped","unconscious","not breathing","weapon","collapse","chemical"]
    if any(term in text for term in urgent_terms):
        score += 3
        reasons.append("Description contains a demonstration urgency indicator.")
    if people and people >= 5:
        score += 2
        reasons.append("Reported affected-person count is five or more.")
    if injuries and injuries.strip():
        score += 1
        reasons.append("Injury information was supplied.")
    services = set()
    if any(x in text for x in ["injur","medical","unconscious","breathing","casualty"]):
        services.add("AMBULANCE")
    if any(x in text for x in ["fire","smoke","explosion","chemical","collapse"]):
        services.add("FIRE")
    if any(x in text for x in ["weapon","violence","threat","crime","traffic"]):
        services.add("POLICE")
    if not services:
        services.add("POLICE")
    missing = []
    if not injuries: missing.append("Injury information not supplied.")
    if not hazards: missing.append("Hazard information not supplied.")
    if not people: missing.append("Affected-person count not supplied.")
    return {"suggested_category":incident_type, "priority_score":min(score,5),
            "suggested_services":sorted(services), "missing_information":missing,
            "explanation":" ".join(reasons) or "No configured urgency indicator was found. Human review remains required."}

HINTS = {
    "TOP SECRET": "RESTRICTED", "SECRET": "RESTRICTED", "RESTRICTED": "RESTRICTED",
    "CONFIDENTIAL": "SENSITIVE", "SENSITIVE": "SENSITIVE",
    "OFFICIAL": "OPERATIONAL", "OFFICIAL-SENSITIVE": "SENSITIVE",
    "OPERATIONAL": "OPERATIONAL", "PUBLIC": "PUBLIC",
}
PII_KEYS = {"callername", "callerphone", "name", "email", "phone", "dob", "dateofbirth"}
OPERATIONAL_KEYS = {
    "incidenttype", "location", "unit", "status", "priority", "assignedagency", "station",
    "action", "resource", "timestamp", "casualties", "departuretime", "arrivaltime",
    "region", "incidentid", "dispatchid", "responderid", "reportid", "eventid", "role",
}

def _normalise_key(key):
    return re.sub(r"[^a-z]", "", str(key).lower())

def _keyword_level(text):
    sample = text.lower()
    if any(word in sample for word in ("national security", "terrorist", "source identity", "covert", "classified")):
        return "RESTRICTED"
    if any(word in sample for word in ("medical", "diagnosis", "injury", "password", "email", "phone")):
        return "SENSITIVE"
    if any(word in sample for word in ("dispatch", "unit", "resource", "location", "incident", "response", "casualty")):
        return "OPERATIONAL"
    return "PUBLIC"

def _label_field(key, value):
    normalised = _normalise_key(key)
    text = "" if value is None else str(value)
    if normalised in PII_KEYS:
        return "SENSITIVE"
    if normalised == "suspectidentifier" and text.strip().upper() not in {"", "N/A", "NONE", "NULL"}:
        return "RESTRICTED"
    if normalised in {"classificationhint", "clearancelevel"}:
        return HINTS.get(text.strip().upper(), "SENSITIVE")
    if normalised == "threatlevel" and text.strip().upper() in {"CRITICAL", "SEVERE"}:
        return "RESTRICTED"
    if normalised in OPERATIONAL_KEYS:
        return "OPERATIONAL"
    return _keyword_level(f"{key} {text}")

def classify_record(record):
    """Field labels from known coursework keys, government hints, and content. The record takes the highest label."""
    if not isinstance(record, dict):
        level = _keyword_level(str(record))
        return {"classification": level, "fields": {}, "review_required": level in ("SENSITIVE", "RESTRICTED"),
                "reason": "Non-object input classified from text only; human review is required."}
    field_labels = {key: _label_field(key, value) for key, value in record.items()}
    hint = HINTS.get(str(record.get("classificationHint", "")).strip().upper())
    levels = list(field_labels.values())
    if hint:
        levels.append(hint)
    level = max(levels, key=lambda item: LEVELS[item]) if levels else "PUBLIC"
    ambiguous = hint is not None and any(label != hint and LEVELS[label] > 0 for label in field_labels.values())
    return {"classification": level, "fields": field_labels,
            "review_required": level in ("SENSITIVE", "RESTRICTED") or ambiguous,
            "reason": "Highest field or classification hint is used. Disagreeing hints are flagged for human review."}

def _coarse_area(value):
    text = "" if value is None else str(value)
    if re.search(r"\d", text):
        return "locality-withheld"
    return text

def create_views(records):
    operational, research = [], []
    counts = {"PUBLIC": 0, "OPERATIONAL": 0, "SENSITIVE": 0, "RESTRICTED": 0}
    categories = []
    for record in records:
        if not isinstance(record, dict):
            record = {"record": record}
        classified = classify_record(record)
        counts[classified["classification"]] = counts.get(classified["classification"], 0) + 1
        op = {k: v for k, v in record.items() if classified["fields"].get(k) in ("PUBLIC", "OPERATIONAL")}
        if op:
            operational.append(op)
        category = record.get("incidentType") or record.get("threatLevel") or record.get("action") or record.get("status") or "unspecified"
        area = record.get("region") or _coarse_area(record.get("location") or record.get("station"))
        categories.append({"category": category, "classification": classified["classification"], "area": area or "unspecified"})
        research_record = {}
        for key, value in op.items():
            if re.search(r"name|email|phone|address|dob|birth|identifier|person|latitude|longitude|caller", key, re.I):
                continue
            if _normalise_key(key) == "location":
                research_record[key] = _coarse_area(value)
            else:
                research_record[key] = value
        research.append(research_record)
    analytics = {"counts_by_classification": counts, "categories": categories,
                 "note": "Aggregates omit names, telephone numbers and suspect identifiers."}
    return {"operational": operational, "analytics": analytics, "research": research,
            "reidentification_note": "Removing direct identifiers does not prove anonymity. Rare incident type and place combinations can still identify a person."}

def run_experiment(experiment_id):
    from .consensus.experiments import run_experiment as execute
    return execute(experiment_id)

def retention_decision(classification, legal_hold=False, age_years=0):
    years = {"PUBLIC": 2, "OPERATIONAL": 7, "SENSITIVE": 10, "RESTRICTED": 20}.get(classification, 20)
    if legal_hold:
        return {"retention_years": years, "action": "HOLD", "archive_status": "ACTIVE",
                "deletion_status": "BLOCKED", "reason": "Legal hold prevents deletion regardless of expiry."}
    if age_years >= years:
        return {"retention_years": years, "action": "DESTROY", "archive_status": "ARCHIVED",
                "deletion_status": "DESTROYED", "reason": "Retention period has elapsed and no legal hold is set. Derived copies may be destroyed; source coursework files are left unchanged."}
    return {"retention_years": years, "action": "RETAIN", "archive_status": "ACTIVE",
            "deletion_status": "NOT_DUE", "reason": "Record remains within its classification retention period."}

def assign_region(location):
    text = (location or "").lower()
    if any(word in text for word in ("exeter", "plymouth", "devon", "cornwall", "taunton", "somerset", "south")):
        return 3
    if any(word in text for word in ("gloucester", "cheltenham", "north")):
        return 1
    return 2

def generate_keypair():
    # HMAC is used as a compact teaching demonstration, not public-key cryptography.
    secret = secrets.token_bytes(32)
    return secret.hex(), hashlib.sha256(secret).hexdigest()
def sign_message(secret_hex, message):
    return hmac.new(bytes.fromhex(secret_hex), message.encode(), hashlib.sha256).hexdigest()
def verify_message(secret_hex, message, signature):
    return hmac.compare_digest(sign_message(secret_hex,message), signature)
