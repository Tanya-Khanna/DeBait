"""Goal-directed containment agent.

The agent is the self-directed control loop that ties the semantic reasoner, the
deterministic policy gate, the scoped broker/worker and independent verification
together. It is NOT a fixed provider sequence: on every iteration it inspects what
it currently knows, decides whether to retrieve more evidence or to intervene,
gates each intervention through policy, executes it, re-reads provider state to
verify the outcome, and repeats until the episode is contained or must be escalated.
"""

from debait.agent.loop import AgentStep, ContainmentAgent
from debait.agent.reasoner import FixtureReasoner, ModelReasoner, Reasoner

__all__ = ["AgentStep", "ContainmentAgent", "FixtureReasoner", "ModelReasoner", "Reasoner"]
