from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from .darktrace import Darktrace

class AIAnalystIncident:
    def __init__(
            self,
            session: Darktrace,
            id: str,
            summary: str,
            score: int,
            details: Optional[List[dict]],
            related_breaches: Optional[List[dict]],
            breach_identifiers: Optional[List[str]],
            raw: Dict[str, Any]
    ):
        self.id = id
        self.summary = summary
        self.score = score
        self.details = details
        self.related_breaches = related_breaches
        self.breach_identifiers = breach_identifiers
        self._raw = raw
        self.session = session

    @classmethod
    def from_json(cls, session: Darktrace, incident: Dict[str, Any]) -> 'AIAnalystIncident':
        return cls(
            session,
            incident["id"],
            incident.get("summary", ""),
            incident["aiaScore"],
            incident.get("details"),
            incident.get("relatedBreaches"),
            [device.get("identifier") for device in incident.get("breachDevices", [])],
            incident
        )

    @classmethod
    def get_incidents(
            cls,
            session: Darktrace,
            init_date: datetime,
            end_date: datetime
    ) -> List['AIAnalystIncident']:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        from_time = int((init_date.replace(tzinfo=timezone.utc) - epoch).total_seconds() * 1000)
        to_time = int((end_date.replace(tzinfo=timezone.utc) - epoch).total_seconds() * 1000)

        query = session.get(f"/aianalyst/incidents?from={from_time}&to={to_time}")
        return [cls.from_json(session, incident) for incident in query] if query else []

    def get_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "score": self.score,
            "details": self.details,
            "related_breaches": self.related_breaches
        }
