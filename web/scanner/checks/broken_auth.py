from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

import httpx

from scanner.checks.base import CheckContext, VulnerabilityCheck
from scanner.core.reporting import ScanFinding


class BrokenAuthCheck(VulnerabilityCheck):
    check_id = "AUTH-001"
    name = "Zayıf Kimlik Doğrulama Kontrolü"
    description = "Varsayılan/kaçak kimlik bilgileri ile oturum açmayı dener."
    severity = "high"

    async def execute(self, context: CheckContext) -> Optional[ScanFinding]:
        credentials: Iterable[Dict[str, str]] = context.metadata.get("credentials", [])
        if not credentials:
            return None

        request_kwargs = self._prepare_request(context.request_kwargs)
        if not request_kwargs:
            return None

        url = f"{context.base_url.rstrip('/')}{context.endpoint}"
        for cred in credentials:
            payload_kwargs = self._inject_credentials(request_kwargs, cred)
            try:
                response = await context.http_client.request(
                    method=context.method,
                    url=url,
                    **payload_kwargs,
                )
            except httpx.RequestError:
                continue

            if self._looks_like_success(response):
                return ScanFinding(
                    check_id=self.check_id,
                    severity=self.severity,
                    endpoint=url,
                    summary="Zayıf kimlik doğrulama tespit edildi",
                    description="Varsayılan veya tahmin edilebilir kimlik bilgileri ile oturum açılabildi.",
                    evidence={
                        "username": cred.get("username"),
                        "status_code": response.status_code,
                        "set_cookie": response.headers.get("set-cookie", "")[:200],
                    },
                    remediation="Varsayılan kimlik bilgilerini devre dışı bırakın ve güçlü parola politikası uygulayın.",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                )
        return None

    def _prepare_request(self, kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if "json" in kwargs or "data" in kwargs:
            return kwargs
        return None

    def _inject_credentials(self, kwargs: Dict[str, Any], cred: Dict[str, str]) -> Dict[str, Any]:
        payload = dict(kwargs)
        if "json" in payload and isinstance(payload["json"], dict):
            payload["json"] = {**payload["json"], **cred}
        if "data" in payload and isinstance(payload["data"], dict):
            payload["data"] = {**payload["data"], **cred}
        return payload

    def _looks_like_success(self, response: httpx.Response) -> bool:
        if response.status_code in (200, 201, 202, 204, 302):
            if "set-cookie" in response.headers:
                return True
            if "token" in response.text.lower():
                return True
        return False


