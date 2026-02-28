from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    id: str
    vulnerability_type: str
    severity: str
    contract: str
    function_name: str
    location: str

    call_trace: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    taint_path: List[str] = field(default_factory=list)

    cross_contract: bool = False
    external_call_depth: int = 0
    privilege_required: bool = False

    exploit_path: Optional[List[str]] = None
    economic_profitability: Optional[float] = None
    gas_cost_estimate: Optional[float] = None

    fork_verified: bool = False
    invariant_broken: bool = False

    consensus_score: float = 0.0
    rejected_reason: Optional[str] = None

    def is_critical(self) -> bool:
        return (
            self.fork_verified
            and self.invariant_broken
            and self.economic_profitability is not None
            and self.economic_profitability > 0
            and self.consensus_score >= 0.85
        )
