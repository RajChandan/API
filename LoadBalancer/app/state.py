from dataclasses import dataclass, field
from itertools import cycle
from typing import Dict, List
import asyncio


@dataclass
class BackendRuntimeState:
    healthy: bool = True
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    passive_failures: int = 0


@dataclass
class LoadBalancerState:
    backends: List[str]
    backend_states: Dict[str, BackendRuntimeState] = field(default_factory=dict)
    selection_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    state_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        if not self.backend_states:
            self.backend_states = {
                backend: BackendRuntimeState() for backend in self.backends
            }
        self.backend_cycle = cycle(self.backends)

    def get_backend_status_view(self) -> Dict[str, bool]:
        return {
            backend: state.healthy for backend, state in self.backend_states.items()
        }
