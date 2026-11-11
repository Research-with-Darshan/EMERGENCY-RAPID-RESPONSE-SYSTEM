"""Small Raft teaching model: terms, votes, log replication and commit quorum."""


def quorum(membership):
    return membership // 2 + 1


class RaftNode:
    def __init__(self, node_id):
        self.id = node_id
        self.term = 0
        self.voted_for = None
        self.log = []
        self.commit_index = 0
        self.role = "follower"
        self.alive = True
        self.group = 0


def make_cluster(ids=("R1", "R2", "R3")):
    return [RaftNode(node_id) for node_id in ids]


def _reachable(left, right):
    return left.alive and right.alive and left.group == right.group


def elect(nodes, candidate_id):
    """Request votes. A leader exists only with a majority of the configured membership."""
    candidate = next(node for node in nodes if node.id == candidate_id)
    log = []
    if not candidate.alive:
        log.append(f"{candidate.id} cannot start an election while unavailable.")
        return {"leader": None, "term": candidate.term, "votes": 0, "quorum": quorum(len(nodes)), "log": log}
    candidate.term += 1
    candidate.voted_for = candidate.id
    candidate.role = "candidate"
    votes = {candidate.id}
    log.append(f"{candidate.id} increments to term {candidate.term} and votes for itself.")
    for peer in nodes:
        if peer.id == candidate.id:
            continue
        if not _reachable(candidate, peer):
            log.append(f"{peer.id} is partitioned or unavailable and does not vote.")
            continue
        if peer.term > candidate.term:
            log.append(f"{peer.id} rejects the vote because its term {peer.term} is newer.")
            continue
        if peer.term == candidate.term and peer.voted_for not in (None, candidate.id):
            log.append(f"{peer.id} rejects the vote; it already voted for {peer.voted_for} in term {peer.term}.")
            continue
        peer.term = candidate.term
        peer.voted_for = candidate.id
        peer.role = "follower"
        votes.add(peer.id)
        log.append(f"{peer.id} grants its vote to {candidate.id} in term {candidate.term}.")
    needed = quorum(len(nodes))
    if len(votes) >= needed:
        candidate.role = "leader"
        for peer in nodes:
            if peer.id != candidate.id and peer.voted_for == candidate.id and peer.term == candidate.term:
                peer.role = "follower"
        log.append(f"{candidate.id} becomes leader with {len(votes)} of {len(nodes)} votes (quorum {needed}).")
        return {"leader": candidate.id, "term": candidate.term, "votes": len(votes), "quorum": needed, "log": log}
    log.append(f"No leader: {len(votes)} vote(s), quorum is {needed}.")
    return {"leader": None, "term": candidate.term, "votes": len(votes), "quorum": needed, "log": log}


def replicate(nodes, leader_id, value):
    """Append one entry and commit it only after a majority has stored it."""
    leader = next(node for node in nodes if node.id == leader_id)
    log = []
    if leader.role != "leader" or not leader.alive:
        log.append(f"{leader.id} has no authority to append; role={leader.role}, alive={leader.alive}.")
        return {"committed": False, "index": None, "acknowledgements": 0, "quorum": quorum(len(nodes)), "log": log}
    entry = {"index": len(leader.log) + 1, "term": leader.term, "value": value}
    leader.log.append(dict(entry))
    stored = {leader.id}
    log.append(f"{leader.id} appends '{value}' at index {entry['index']} in term {entry['term']}.")
    for peer in nodes:
        if peer.id == leader.id:
            continue
        if not _reachable(leader, peer):
            log.append(f"{peer.id} does not acknowledge the entry.")
            continue
        if peer.term > leader.term:
            leader.role = "follower"
            log.append(f"{peer.id} has a newer term. {leader.id} steps down. Entry is not committed.")
            return {"committed": False, "index": entry["index"], "acknowledgements": len(stored), "quorum": quorum(len(nodes)), "log": log}
        peer.log.append(dict(entry))
        peer.term = leader.term
        stored.add(peer.id)
        log.append(f"{peer.id} stores '{value}'.")
    needed = quorum(len(nodes))
    if len(stored) >= needed:
        for node in nodes:
            if node.id in stored:
                node.commit_index = entry["index"]
        log.append(f"Committed '{value}' at index {entry['index']} with {len(stored)} of {len(nodes)} copies.")
        return {"committed": True, "index": entry["index"], "acknowledgements": len(stored), "quorum": needed, "log": log}
    log.append(f"Not committed: {len(stored)} copy(ies), quorum is {needed}.")
    return {"committed": False, "index": entry["index"], "acknowledgements": len(stored), "quorum": needed, "log": log}


def isolate_all(nodes):
    for index, node in enumerate(nodes):
        node.group = index + 1


def election_storm(rounds=3):
    """Each node votes for itself before any RequestVote is exchanged, so no quorum forms."""
    nodes = make_cluster()
    log = ["Three followers time out together. Each begins an election and votes for itself before hearing the others."]
    terms = []
    for _ in range(rounds):
        for node in nodes:
            node.term += 1
            node.voted_for = node.id
            node.role = "candidate"
        term = nodes[0].term
        terms.append(term)
        grants = []
        for candidate in nodes:
            votes = 1
            for peer in nodes:
                if peer.id == candidate.id:
                    continue
                if peer.term == candidate.term and peer.voted_for not in (None, candidate.id):
                    log.append(f"{peer.id} refuses {candidate.id} in term {candidate.term}; already voted for {peer.voted_for}.")
                    continue
                votes += 1
            grants.append(votes)
            log.append(f"{candidate.id} collects {votes} vote(s) in term {candidate.term}; quorum is {quorum(len(nodes))}.")
        if any(votes >= quorum(len(nodes)) for votes in grants):
            log.append("A stable leader appeared; the storm setup is invalid.")
            break
    committed = any(node.commit_index > 0 for node in nodes)
    log.append("No stable leader. Commit stays blocked while terms advance.")
    return {"nodes": nodes, "terms": terms, "committed": committed, "log": log}


def network_partition():
    nodes = make_cluster()
    log = ["Control: all three nodes can communicate."]
    election = elect(nodes, "R1")
    log.extend(election["log"])
    healthy = replicate(nodes, "R1", "incident-status-verified")
    log.extend(healthy["log"])
    isolate_all(nodes)
    log.append("Fault: each node is placed in its own partition, so no side holds a majority of the three-node membership.")
    failed = replicate(nodes, "R1", "incident-status-closed")
    log.extend(failed["log"])
    return {
        "nodes": nodes,
        "control_committed": healthy["committed"],
        "committed": failed["committed"],
        "log": log,
    }


def leadership_churn():
    nodes = make_cluster()
    log = []
    first = elect(nodes, "R1")
    log.extend(first["log"])
    leader = nodes[0]
    leader.log.append({"index": 1, "term": leader.term, "value": "unreplicated-dispatch-order"})
    log.append(f"{leader.id} holds unreplicated-dispatch-order locally and loses leadership before any follower stores it.")
    leader.alive = False
    leader.role = "follower"
    second = elect(nodes, "R2")
    log.extend(second["log"])
    replacement = replicate(nodes, "R2", "confirmed-dispatch-order")
    log.extend(replacement["log"])
    leaked = any(entry["value"] == "unreplicated-dispatch-order" and node.commit_index >= entry["index"] for node in nodes for entry in node.log)
    log.append("The unreplicated order is absent from the new leader's committed log.")
    return {"nodes": nodes, "committed_lost_entry": leaked, "replacement_committed": replacement["committed"], "log": log}
