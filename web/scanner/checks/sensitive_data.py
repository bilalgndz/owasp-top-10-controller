from __future__ import annotations

import re
from typing import Optional

import httpx

from scanner.checks.base import CheckContext, VulnerabilityCheck
from scanner.core.reporting import ScanFinding


SENSITIVE_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA|DSA|EC)? PRIVATE KEY-----"),
    "Email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
}


class SensitiveDataExposureCheck(VulnerabilityCheck):
    check_id = "DATA-001"
    name = "Hassas Veri Sızıntısı Kontrolü"
    description = "Yanıtlarda yaygın hassas veri kalıplarını arar."
    severity = "medium"

    async def execute(self, context: CheckContext) -> Optional[ScanFinding]:
        url = f"{context.base_url.rstrip('/')}{context.endpoint}"
        try:
            response = await context.http_client.request(
                method=context.method,
                url=url,
                **context.request_kwargs,
            )
        except httpx.RequestError:
            return None

        matches = self._find_sensitive_data(response.text)
        if not matches:
            return None

        return ScanFinding(
            check_id=self.check_id,
            severity=self.severity,
            endpoint=url,
            summary="Hassas veri sızıntısı belirtisi",
            description="Yanıtta hassas veri kalıpları bulundu. Bu, veri sızıntısına işaret edebilir.",
            evidence={
                "matches": matches,
                "status_code": response.status_code,
            },
            remediation="Yanıtlarda gereksiz veri göndermeyin ve hassas bilgileri maskeleyin.",
            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
        )

    def _find_sensitive_data(self, body: str) -> dict[str, str]:
        findings: dict[str, str] = {}
        for name, pattern in SENSITIVE_PATTERNS.items():
            match = pattern.search(body)
            if match:
                findings[name] = match.group(0)[:120]
        return findings


