from typing import Any, Dict, Optional, List
from .darktrace import Darktrace


class Device:
    @classmethod
    def from_json(cls, session: Darktrace, data: Dict[str, Any]) -> 'Device':
        return cls(
            session=session,
            did=data.get("did"),
            ip=data.get("ip"),
            hostname=data.get("hostname"),
            typename=data.get("typename"),
            os=data.get("os"),
            first_seen=data.get("firstSeen"),
            last_seen=data.get("lastSeen"),
            tags=[]
        )

    @classmethod
    def get_assets(cls, session: Darktrace) -> List['Device']:
        devices_data = session.get("/devices")
        return [cls.from_json(session, data) for data in devices_data] if devices_data else []
    @classmethod
    def get_using_tag(cls, session: Darktrace, tag: str) -> List['Device']:
        query = f"/devicesearch?query=tag:{tag}"
        devices = session.get(query)
        return [cls.from_json(session, device) for device in devices] if devices else []

    def __init__(
            self,
            session: Darktrace,
            did: str,
            ip: Optional[str],
            hostname: Optional[str],
            typename: Optional[str],
            os: Optional[str],
            first_seen: Optional[int],
            last_seen: Optional[int],
            tags: List[str]
    ):
        self.session = session
        self.did = did
        self.ip = ip
        self.hostname = hostname
        self.typename = typename
        self.os = os
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.tags = tags

    def get_details(self) -> Dict[str, Any]:
        query_uri = f"/devices/{self.did}"
        return self.session.get(query_uri)

    def get_model_breaches(self) -> List[Dict[str, Any]]:
        query_uri = f"/modelbreaches?did={self.did}"
        return self.session.get(query_uri) or []

    def get_tags(self) -> List[str]:
        query_uri = f"/tags/entities?did={self.did}"
        response = self.session.get(query_uri)
        if response:
            return [tag['name'] for tag in response]
        return []