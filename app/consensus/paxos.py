"""Single-decree Paxos teaching model with durable acceptor state."""


def quorum_of(membership):
    return membership // 2 + 1


class Acceptor:
    def __init__(self, acceptor_id):
        self.id = acceptor_id
        self.promised = -1
        self.accepted_n = None
        self.accepted_v = None
        self.alive = True
        self.durable = True


def make_acceptors(count=3):
    return [Acceptor(f"A{index}") for index in range(1, count + 1)]


def propose(acceptors, ballot, value, quorum=None):
    """Prepare then accept. A value is chosen only when a quorum of durable acceptors accepts it."""
    membership = len(acceptors)
    needed = quorum_of(membership) if quorum is None else quorum
    log = [f"Proposer ballot {ballot} offers '{value}'. Membership {membership}, configured quorum {needed}."]
    if needed > membership or needed < quorum_of(membership):
        log.append("Configuration rejected: the quorum must be a majority and cannot exceed membership.")
        return {"status": "REJECTED", "committed": False, "value": None, "log": log}
    promises = []
    for acceptor in acceptors:
        if not acceptor.alive:
            log.append(f"{acceptor.id} is unavailable and sends no promise.")
            continue
        if not acceptor.durable:
            log.append(f"{acceptor.id} has no durable promised or accepted state. Unsafe to continue.")
            return {"status": "SAFE_STOP", "committed": False, "value": None, "log": log}
        if ballot > acceptor.promised:
            acceptor.promised = ballot
            promises.append(acceptor)
            remembered = acceptor.accepted_v if acceptor.accepted_v is not None else "none"
            log.append(f"{acceptor.id} promises ballot {ballot} and reports accepted value '{remembered}'.")
        else:
            log.append(f"{acceptor.id} rejects ballot {ballot}; it promised {acceptor.promised}.")
    if len(promises) < needed:
        log.append(f"Prepare failed: {len(promises)} promise(s), quorum is {needed}. No value is chosen.")
        return {"status": "NO_QUORUM", "committed": False, "value": None, "log": log}
    chosen = value
    highest = -1
    for acceptor in promises:
        if acceptor.accepted_n is not None and acceptor.accepted_n >= highest:
            highest = acceptor.accepted_n
            chosen = acceptor.accepted_v
    if chosen != value:
        log.append(f"Quorum overlap preserves previously accepted value '{chosen}' instead of '{value}'.")
    accepted = []
    for acceptor in promises:
        if ballot >= acceptor.promised:
            acceptor.accepted_n = ballot
            acceptor.accepted_v = chosen
            accepted.append(acceptor)
            log.append(f"{acceptor.id} accepts '{chosen}' at ballot {ballot}.")
    if len(accepted) < needed:
        log.append("Accept phase missed the quorum. No value is chosen.")
        return {"status": "NO_QUORUM", "committed": False, "value": None, "log": log}
    log.append(f"Chosen '{chosen}' with {len(accepted)} acceptors.")
    return {"status": "CHOSEN", "committed": True, "value": chosen, "log": log}


def state_loss():
    acceptors = make_acceptors()
    log = ["Control: three durable acceptors choose an allocation."]
    first = propose(acceptors, 1, "resource-AMB-001")
    log.extend(first["log"])
    for acceptor in acceptors:
        acceptor.durable = False
        acceptor.promised = -1
        acceptor.accepted_n = None
        acceptor.accepted_v = None
    log.append("Fault: every acceptor loses the promised ballot and the accepted value from durable storage.")
    second = propose(acceptors, 2, "resource-FIRE-009")
    log.extend(second["log"])
    return {"control_value": first["value"], "status": second["status"], "committed": second["committed"], "log": log}


def majority_loss():
    acceptors = make_acceptors()
    acceptors[1].alive = False
    acceptors[2].alive = False
    log = ["Fault: two of three acceptors are unavailable, so a majority cannot be contacted."]
    outcome = propose(acceptors, 1, "resource-POL-001")
    log.extend(outcome["log"])
    return {"status": outcome["status"], "committed": outcome["committed"], "log": log}


def quorum_misconfiguration():
    acceptors = make_acceptors()
    log = ["Fault: quorum is configured as 4 while only 3 acceptors are members."]
    outcome = propose(acceptors, 1, "resource-AMB-002", quorum=4)
    log.extend(outcome["log"])
    untouched = all(acceptor.accepted_v is None for acceptor in acceptors)
    log.append("No acceptor stored a value after the configuration check failed." if untouched else "Configuration check failed to prevent accepts.")
    return {"status": outcome["status"], "committed": outcome["committed"], "untouched": untouched, "log": log}
