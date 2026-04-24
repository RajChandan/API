from dataclasses import dataclass, field
from itertools import cycle
from typing import Dict, List
import asyncio
import time

from app.config import ServicePolicy

@dataclass
class BackendRuntimeState:
    healthy: bool = True
   


@dataclass
class ServiceRuntimeState:
    name: str
    prefix: str
    backends: List[str]
    policy:ServicePolicy
    backend_states: Dict[str, BackendRuntimeState] = field(default_factory=dict)

    def __post_init__(self):
        self.backend_cycle = cycle(self.backends)

        if not self.backend_states:
            self.backend_states = {
                backend: BackendRuntimeState() for backend in self.backends
            }


@dataclass
class GatewayState:
    services: Dict[str, ServiceRuntimeState]


# @dataclass
# class RateLimitEntry:
#     window_start: float
#     count: int = 0


# @dataclass
# class LoadBalancerState:
#     backends: List[str]
#     backend_states: Dict[str, BackendRuntimeState] = field(default_factory=dict)
#     selection_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
#     state_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

#     is_draining: bool = False
#     inflight_requests: int = 0
#     inflight_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

#     rate_limit_store: Dict[str, RateLimitEntry] = field(default_factory=dict)
#     rate_limit_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
#     last_rate_limit_cleanup_ts: float = field(default_factory=time.time)

#     def __post_init__(self):
#         if not self.backend_states:
#             self.backend_states = {
#                 backend: BackendRuntimeState() for backend in self.backends
#             }
#         self.backend_cycle = cycle(self.backends)

#     def get_backend_status_view(self) -> Dict[str, bool]:
#         return {
#             backend: state.healthy for backend, state in self.backend_states.items()
#         }
