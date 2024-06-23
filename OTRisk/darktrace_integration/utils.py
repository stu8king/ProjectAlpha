from typing import Any, Dict

def nget(d: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return None
    return d
