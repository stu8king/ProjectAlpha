import datetime
from typing import Any, Dict, List, Optional
from .darktrace import Darktrace
from .utils import nget
from .device import Device
class ModelBreach:
    @classmethod
    def from_json(cls, session: Darktrace, model: Dict[str, Any]) -> 'ModelBreach':
        return cls(
            session,
            model["pbid"],
            float(model["score"]),
            datetime.datetime.fromtimestamp(model["time"] / 1000),
            model,
            model.get("device", {}).get("did")
        )

    @classmethod
    def get_model_breaches(cls, session: Darktrace, device: Optional[Device] = None) -> List['ModelBreach']:
        query = "/modelbreaches"
        if device:
            query += f"?did={device.did}"
        models = session.get(query)
        return [cls.from_json(session, model) for model in models] if models else []

    def __init__(
        self,
        session: Darktrace,
        pbid: str,
        score: float,
        time: datetime.datetime,
        raw: Dict[str, Any],
        device_id: Optional[str]
    ):
        self.session = session
        self.pbid = pbid
        self.score = score
        self.time = time
        self.raw = raw
        self.device_id = device_id

    def get_summary(self) -> Dict[str, Any]:
        return {
            "model_name": nget(self.raw, "model", "then", "name"),
            "breach_time": self.time.isoformat(),
            "score": self.score,
            "description": nget(self.raw, "model", "then", "description"),
            "actions": nget(self.raw, "model", "then", "actions")
        }
