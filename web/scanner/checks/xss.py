from __future__ import annotations

import html
import secrets
from copy import deepcopy
from typing import Any, Dict, Optional

import httpx

from scanner.checks.base import CheckContext, VulnerabilityCheck
from scanner.core.reporting import ScanFinding


class ReflectedXSSCheck(VulnerabilityCheck):
    check_id = "XSS-001"
    name = "Reflected XSS Kontrolü"
    description = "Reflected XSS ihtimallerini rastgele token ile sınar."
    severity = "high"

    async def execute(self, context: CheckContext) -> Optional[ScanFinding]:
        token = secrets.token_hex(6)
        payload = f"<svg/onload=alert('{token}')>"
        kwargs = deepcopy(context.request_kwargs)
        kwargs.setdefault("headers", {})
        kwargs["headers"]["X-Vuln-Scanner"] = "xss-probe"

        params = kwargs.get("params") or {}
        if isinstance(params, dict):
            params.setdefault("q", payload)
            kwargs["params"] = params
        elif isinstance(params, list):
            params.append(("q", payload))
            kwargs["params"] = params
        else:
            kwargs["params"] = {"q": payload}

        url = f"{context.base_url.rstrip('/')}{context.endpoint}"
        try:
            response = await context.http_client.request(
                method=context.method,
                url=url,
                **kwargs,
            )
        except httpx.RequestError:
            return None

        if token in response.text and payload in response.text:
            return self._build_finding(url, payload, response.text)

        escaped = html.escape(payload)
        if token in response.text and escaped in response.text:
            return self._build_finding(url, payload, response.text, escaped=True)
        return None

    def _build_finding(self, url: str, payload: str, body: str, escaped: bool = False) -> ScanFinding:
        note = "Payload HTML escape edilmeden geri döndü." if not escaped else "Payload kısmen escape edildi."
        return ScanFinding(
            check_id=self.check_id,
            severity=self.severity,
            endpoint=url,
            summary="Reflected XSS belirtisi tespit edildi",
            description=(
                "Uygulama, gönderilen payload'u yanıtta token ile birlikte döndürdü. "
                f"{note} Bu durum XSS istismarına yol açabilir."
            ),
            evidence={
                "payload": payload,
                "response_snippet": body[:500],
            },
            remediation="Kullanıcı girdilerini HTML encode edin ve içerik güvenlik politikaları uygulayın.",
            references=["https://owasp.org/www-community/attacks/xss/"],
        )


