"""Teaching simulations of Raft, Paxos and a quorum-based BFT check.

These modules keep node state, messages and quorum decisions in process memory.
They are not a multi-datacentre deployment.
"""

from .experiments import run_experiment

__all__ = ["run_experiment"]
