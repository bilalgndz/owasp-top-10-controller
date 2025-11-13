from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from scanner.core.http_client import HttpClient

from scanner.core.reporting import ScanFinding


@dataclass
class CheckContext:
    base_url: str
    endpoint: str
    method: str
    request_kwargs: Dict[str, Any]
    metadata: Dict[str, Any]
    http_client: "HttpClient"


class VulnerabilityCheck(abc.ABC):
    check_id: str
    name: str
    description: str
    severity: str

    def __init__(self, *, weight: int = 1) -> None:
        self.weight = weight

    @abc.abstractmethod
    async def execute(self, context: CheckContext) -> Optional[ScanFinding]:
        """Spesifik kontrolü uygula. Bulgu varsa `ScanFinding` dön."""


