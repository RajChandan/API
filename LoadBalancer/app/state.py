from dataclasses import dataclass, field
from itertools import cycle
from typing import Dict, List
import asyncio


@dataclass
class LoadBalancerState:
    backends: List[str]
    backend_status: Dict[str, bool] = field(default_factory=dict)
    selection_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        if not self.backend_status:
            self.backend_status = {backend: True for backend in self.backends}
        self.backend_cycle = cycle(self.backends)
