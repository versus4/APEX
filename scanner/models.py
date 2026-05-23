"""Small shared data models used by the scanner runtime."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Tuple


@dataclasses.dataclass(frozen=True)
class Finding:
    module: str
    detail: str
    payload: str = ""
    severity: str = "INFO"
    category: str = "misc"
    url: str = ""
    param: str = ""
    id: str = ""
    evidence_level: str = "possible"
    confidence_score: int = 0
    confirmed: bool = False
    speculative: bool = False
    exposure_type: str = "finding"
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_tuple(self) -> Tuple[str, str, str, str]:
        return (self.module, self.detail, self.payload, self.severity)

    def as_json(self) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "module": self.module,
            "category": self.category,
            "detail": self.detail,
            "payload": self.payload,
            "url": self.url,
            "param": self.param,
            "severity": self.severity,
            "evidence_level": self.evidence_level,
            "confidence_score": self.confidence_score,
            "confirmed": self.confirmed,
            "speculative": self.speculative,
            "exposure_type": self.exposure_type,
        }
        data.update(self.metadata)
        return data


@dataclasses.dataclass
class ScanConfig:
    delay: float = 0.0
    timeout: float = 5.0
    module_timeout: float = 90.0
    module_request_budget: int = 0
    max_body: int = 262144
    user_agent: str = "Apex (authorized assessment)"
    headers: Dict[str, str] = dataclasses.field(default_factory=dict)
    tls_verify: bool = True
    js_render: bool = False


ScanFindings = List[Any]
