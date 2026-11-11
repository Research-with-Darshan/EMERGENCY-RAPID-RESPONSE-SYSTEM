"""Execute the nine coursework fault experiments and record what the simulations did."""

from . import bft, paxos, raft


SUBSYSTEMS = {
    "Regional Incident Database": "Raft",
    "Emergency Dispatch Service": "Raft",
    "Resource Allocation Service": "Paxos",
    "National Audit Log": "BFT",
    "Intelligence Distribution Service": "BFT",
}


def _package(experiment_id, protocol, fault, configuration, result_code, log, impact, mitigation, committed_under_fault):
    return {
        "id": experiment_id,
        "protocol": protocol,
        "fault": fault,
        "initial_configuration": configuration,
        "fault_injected": fault,
        "execution_log": log,
        "observed_result": result_code,
        "security_impact": impact,
        "mitigation": mitigation,
        "committed_under_fault": committed_under_fault,
        "test_result": "PASS" if not committed_under_fault else "FAIL",
    }


def run_experiment(experiment_id):
    if experiment_id == "BFT-01":
        outcome = bft.equivocation()
        return _package(
            experiment_id, "BFT", "Equivocation",
            "Four registered validators, quorum 3, one primary.",
            "DETECTED", outcome["log"],
            "Integrity: a primary sent two values for one sequence. Neither value was committed.",
            "Compare authenticated proposal digests and refuse to commit when they differ.",
            outcome["committed"],
        )
    if experiment_id == "BFT-02":
        outcome = bft.sybil()
        return _package(
            experiment_id, "BFT", "Sybil attack",
            "Four registered validators plus one unregistered identity.",
            "REJECTED", outcome["log"],
            "The unregistered vote was ignored. It could not commit the forged value.",
            "Admit validators only through an authorised registry and drop unknown identities.",
            outcome["forged_committed"],
        )
    if experiment_id == "BFT-03":
        outcome = bft.key_compromise()
        committed = outcome["revoked"] or outcome["stale"] or not outcome["replacement"]
        return _package(
            experiment_id, "BFT", "Validator key compromise",
            "Validator V4 at key version 1, then revoked, then replaced at version 2.",
            "MITIGATED", outcome["log"],
            "Messages authenticated with the revoked version were rejected.",
            "Revoke the key version and require the replacement version for later votes.",
            committed,
        )
    if experiment_id == "PAXOS-04":
        outcome = paxos.state_loss()
        return _package(
            experiment_id, "PAXOS", "State loss",
            "Three acceptors. A value was chosen, then every acceptor lost durable state.",
            "SAFE_STOP", outcome["log"],
            "Continuing after total loss of accepted state could choose a conflicting value.",
            "Stop when durable promised or accepted state is missing.",
            outcome["committed"],
        )
    if experiment_id == "PAXOS-05":
        outcome = paxos.majority_loss()
        return _package(
            experiment_id, "PAXOS", "Majority loss",
            "Three acceptors, quorum 2, two acceptors unavailable.",
            "NO_QUORUM", outcome["log"],
            "Availability: no allocation value was chosen.",
            "Do not report a value as chosen without a majority of promises and accepts.",
            outcome["committed"],
        )
    if experiment_id == "PAXOS-06":
        outcome = paxos.quorum_misconfiguration()
        return _package(
            experiment_id, "PAXOS", "Quorum misconfiguration",
            "Three acceptors with quorum incorrectly set to 4.",
            "REJECTED", outcome["log"],
            "An impossible quorum would stall or, if set below a majority, could break safety.",
            "Reject a quorum that is not a majority of the current membership.",
            outcome["committed"] or not outcome["untouched"],
        )
    if experiment_id == "RAFT-07":
        outcome = raft.network_partition()
        return _package(
            experiment_id, "RAFT", "Network partition",
            "Three Raft nodes. A value commits while connected, then each node is isolated.",
            "NO_QUORUM", outcome["log"],
            "The isolated leader could not commit a newer incident status.",
            "Commit only after a majority of the configured membership stores the entry.",
            outcome["committed"],
        )
    if experiment_id == "RAFT-08":
        outcome = raft.election_storm()
        return _package(
            experiment_id, "RAFT", "Election storms",
            "Three nodes timeout together for three rounds and each votes for itself.",
            "DEGRADED", outcome["log"],
            "Availability: terms advance and no entry is committed while leadership is unstable.",
            "Do not commit during an election, and use randomised timeouts in a full Raft implementation.",
            outcome["committed"],
        )
    if experiment_id == "RAFT-09":
        outcome = raft.leadership_churn()
        return _package(
            experiment_id, "RAFT", "Leadership churn",
            "Leader R1 appends locally, fails, and R2 is elected with the two remaining nodes.",
            "DEGRADED", outcome["log"],
            "An order that was never replicated was not treated as committed by the new leader.",
            "Commit only entries stored by a majority. A new leader uses its own log.",
            outcome["committed_lost_entry"],
        )
    raise KeyError(experiment_id)


def all_ids():
    return [f"BFT-0{i}" for i in range(1, 4)] + [f"PAXOS-0{i}" for i in range(4, 7)] + [f"RAFT-0{i}" for i in range(7, 10)]
