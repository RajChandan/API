from typing import Optional


def match_service(path: str, gateway_state):
    matched_service = None
    longest_prefix = ""

    for service in gateway_state.services.values():
        if path.startswith(service.prefix):
            if len(service.prefix) > len(longest_prefix):
                matched_service = service
                longest_prefix = service.prefix
    return matched_service
