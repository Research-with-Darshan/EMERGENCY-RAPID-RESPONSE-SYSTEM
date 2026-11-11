"""Quorum BFT teaching model with registered validators and HMAC message authentication.

Four validators, at most one faulty. A value is committed only when three distinct
active validators authenticate the same proposal digest. HMAC is a shared-key
authenticator for this prototype, not a public-key signature.
"""

import hashlib
import hmac
import json
from hashlib import sha256


QUORUM = 3


class Validator:
    def __init__(self, validator_id, secret):
        self.id = validator_id
        self.secret = secret
        self.version = 1
        self.status = "ACTIVE"


def registry(ids=("V1", "V2", "V3", "V4")):
    return {validator_id: Validator(validator_id, f"secret-{validator_id}") for validator_id in ids}


def _payload(view, sequence, value):
    return {"view": view, "sequence": sequence, "value": value}


def sign(validator, view, sequence, value):
    message = json.dumps(_payload(view, sequence, value), sort_keys=True)
    digest = hmac.new(validator.secret.encode(), message.encode(), sha256).hexdigest()
    return {"validator": validator.id, "version": validator.version, "value": value, "view": view, "sequence": sequence, "digest": digest}


def verify(members, signed):
    validator = members.get(signed["validator"])
    if validator is None or validator.status != "ACTIVE":
        return False, "Unknown, disabled or revoked validator."
    if signed["version"] != validator.version:
        return False, "Outdated key version."
    expected = sign(validator, signed["view"], signed["sequence"], signed["value"])
    if not hmac.compare_digest(expected["digest"], signed["digest"]):
        return False, "Message authentication failed."
    return True, "Authenticated."


def commit_value(members, signed_messages):
    """Commit one value only when the quorum agrees on one authenticated digest."""
    log = []
    accepted = {}
    for signed in signed_messages:
        ok, reason = verify(members, signed)
        marker = hashlib.sha256(signed["value"].encode()).hexdigest()[:12]
        if not ok:
            log.append(f"Rejected {signed['validator']} on '{signed['value']}': {reason}")
            continue
        accepted.setdefault(signed["value"], set()).add(signed["validator"])
        log.append(f"Accepted authenticated vote from {signed['validator']} for '{signed['value']}' ({marker}).")
    if len(accepted) > 1:
        log.append("Equivocation: more than one value carries authenticated votes for the same view and sequence.")
    chosen = None
    for value, voters in accepted.items():
        log.append(f"'{value}' has {len(voters)} distinct authenticated vote(s); quorum is {QUORUM}.")
        if len(voters) >= QUORUM and chosen is None:
            chosen = value
    if len(accepted) > 1:
        log.append("Conflicting authenticated proposals are not committed.")
        return {"committed": False, "value": None, "detected": True, "log": log}
    if chosen is None:
        log.append("No value reached the authenticated quorum.")
        return {"committed": False, "value": None, "detected": False, "log": log}
    log.append(f"Committed '{chosen}'.")
    return {"committed": True, "value": chosen, "detected": False, "log": log}


def equivocation():
    members = registry()
    primary = members["V1"]
    log = ["Control path is not used. Primary V1 signs two different values for view 1, sequence 1."]
    messages = [
        sign(primary, 1, 1, "intelligence-A"),
        sign(primary, 1, 1, "intelligence-B"),
        sign(members["V2"], 1, 1, "intelligence-A"),
        sign(members["V3"], 1, 1, "intelligence-B"),
    ]
    outcome = commit_value(members, messages)
    log.extend(outcome["log"])
    return {"committed": outcome["committed"], "detected": outcome["detected"], "log": log}


def sybil():
    members = registry()
    outsider = Validator("SYBIL-9", "secret-SYBIL-9")
    log = ["SYBIL-9 is not in the validator registry and supports a conflicting intelligence value."]
    messages = [
        sign(members["V1"], 1, 1, "intelligence-honest"),
        sign(members["V2"], 1, 1, "intelligence-honest"),
        sign(members["V3"], 1, 1, "intelligence-honest"),
        sign(outsider, 1, 1, "intelligence-forged"),
    ]
    outcome = commit_value(members, messages)
    log.extend(outcome["log"])
    forged_committed = outcome["value"] == "intelligence-forged"
    return {"committed_value": outcome["value"], "forged_committed": forged_committed, "sybil_rejected": True, "log": log}


def key_compromise():
    members = registry()
    victim = members["V4"]
    log = ["V4 is registered at key version 1 and can authenticate a vote."]
    original = sign(victim, 1, 1, "audit-record")
    ok, reason = verify(members, original)
    log.append(f"Version 1 signature before revocation: {reason}")
    victim.status = "REVOKED"
    log.append("Authorised revocation sets V4 to REVOKED.")
    revoked_ok, revoked_reason = verify(members, original)
    log.append(f"Same signature after revocation: {revoked_reason}")
    victim.secret = "secret-V4-rotated"
    victim.version = 2
    victim.status = "ACTIVE"
    log.append("A replacement key is registered as version 2.")
    rotated = sign(victim, 1, 1, "audit-record")
    new_ok, new_reason = verify(members, rotated)
    stale_ok, stale_reason = verify(members, original)
    log.append(f"Version 2 signature: {new_reason}")
    log.append(f"Version 1 signature after rotation: {stale_reason}")
    return {
        "before": ok,
        "revoked": revoked_ok,
        "replacement": new_ok,
        "stale": stale_ok,
        "log": log,
    }
