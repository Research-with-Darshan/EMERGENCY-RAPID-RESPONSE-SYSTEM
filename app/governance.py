"""Executable checks for the five post-deployment governance scenarios.

Each function calls the policy engine, retention rules, or a consensus simulation.
None of them grants access by relaxing Bell-LaPadula or Biba.
"""

from .consensus import bft, raft
from .engines import retention_decision
from .security import evaluate_policy


def research_organisation_request():
    """An organisation with no operational role asks to read restricted intelligence."""
    outsider = {"role": "ANONYMOUS", "status": "ACTIVE"}
    decision = evaluate_policy(outsider, "intelligence:read", "RESTRICTED", "RESTRICTED", purpose="RESEARCH")
    return {
        "id": "E1",
        "title": "Research organisation requests unrestricted intelligence access",
        "datasets": ["intelligence.json"],
        "properties": ["confidentiality"],
        "decision": decision["decision"],
        "failed_rules": decision["failed_rules"],
        "explanation": decision["explanation"],
        "impact": "Unrestricted release would expose suspect identifiers and threat reporting in intelligence.json. The matrix has no research role, and the purpose is not OPERATIONS.",
    }


def responder_classified_request():
    """A police officer asks to read restricted national-security intelligence."""
    officer = {"role": "POLICE", "status": "ACTIVE"}
    decision = evaluate_policy(officer, "intelligence:read", "RESTRICTED", "RESTRICTED", region_id=2, assigned_region_id=2)
    return {
        "id": "E2",
        "title": "Emergency responders request classified national-security information",
        "datasets": ["intelligence.json", "responders.json"],
        "properties": ["confidentiality", "operational effectiveness"],
        "decision": decision["decision"],
        "failed_rules": decision["failed_rules"],
        "explanation": decision["explanation"],
        "impact": "Police clearance is OPERATIONAL and the matrix does not grant intelligence:read. Granting it would collapse the boundary between response data and restricted intelligence.",
    }


def regional_datacentre_loss():
    """South is isolated. A previously committed Raft entry stays committed; a new one does not."""
    outcome = raft.network_partition()
    return {
        "id": "E3",
        "title": "A regional datacentre becomes permanently unavailable",
        "datasets": ["incidents.json", "dispatch.json"],
        "properties": ["availability", "integrity"],
        "decision": "NO_NEW_COMMIT" if not outcome["committed"] else "UNSAFE_COMMIT",
        "control_committed": outcome["control_committed"],
        "new_value_committed": outcome["committed"],
        "explanation": "The three logical regions share one teaching process. Isolating every Raft node removes the majority required to commit a new incident status. The earlier committed value is not rewritten.",
        "log": outcome["log"],
    }


def audit_validator_compromise():
    """A national-audit validator key is revoked and an old authenticator is rejected."""
    outcome = bft.key_compromise()
    safe = outcome["before"] and not outcome["revoked"] and outcome["replacement"] and not outcome["stale"]
    return {
        "id": "E4",
        "title": "Validator credentials protecting the national audit system are compromised",
        "datasets": ["audit.json"],
        "properties": ["integrity", "authenticity"],
        "decision": "MITIGATED" if safe else "REVIEW",
        "before_revocation": outcome["before"],
        "revoked_key_accepted": outcome["revoked"],
        "replacement_accepted": outcome["replacement"],
        "stale_key_accepted": outcome["stale"],
        "explanation": "Revocation rejects the old authenticator. A replacement version can authenticate later votes. HMAC here is a shared-key teaching substitute, not a public-key signature.",
        "log": outcome["log"],
    }


def twenty_year_retention():
    """Restricted records are kept for 20 years. Destruction is refused while a legal hold is set."""
    within = retention_decision("RESTRICTED", age_years=19)
    expired = retention_decision("RESTRICTED", age_years=20)
    held = retention_decision("RESTRICTED", legal_hold=True, age_years=25)
    return {
        "id": "E5",
        "title": "Regulations require emergency-response records to be retained for twenty years",
        "datasets": ["incidents.json", "dispatch.json", "responders.json", "intelligence.json", "audit.json"],
        "properties": ["confidentiality", "storage", "integrity"],
        "within_period": within,
        "at_expiry": expired,
        "legal_hold": held,
        "explanation": "RESTRICTED uses 20 years. PUBLIC, OPERATIONAL and SENSITIVE keep shorter demonstration periods. A legal hold blocks destruction. Original files in data/source are not deleted.",
    }


def all_scenarios():
    return [
        research_organisation_request(),
        responder_classified_request(),
        regional_datacentre_loss(),
        audit_validator_compromise(),
        twenty_year_retention(),
    ]
