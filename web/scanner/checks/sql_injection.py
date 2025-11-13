from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, Iterable, Optional

import httpx

from scanner.checks.base import CheckContext, VulnerabilityCheck
from scanner.core.reporting import ScanFinding


SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "pg_query",
    "ODBC SQL Server Driver",
    "Syntax error in string in query expression",
    "Warning: sqlite_",
    "SQLSTATE[HY000]",
    "unterminated quoted string at or near",
]


class SQLInjectionCheck(VulnerabilityCheck):
    check_id = "SQLI-001"
    name = "SQL Injection Kontrolü"
    description = "Parametrelerde SQL Injection izlerini arar."
    severity = "critical"

    payloads: Iterable[str] = (
        "' OR 1=1 --",
        "\" OR \"1\"=\"1\" --",
        "'; WAITFOR DELAY '0:0:3' --",
        "' UNION SELECT NULL,NULL,NULL --",
        "') OR ('1'='1",
    )

    async def execute(self, context: CheckContext) -> Optional[ScanFinding]:
        url = f"{context.base_url.rstrip('/')}{context.endpoint}"
        for payload in self.payloads:
            kwargs = self._build_payload(context.request_kwargs, payload)
            try:
                response = await context.http_client.request(
                    method=context.method,
                    url=url,
                    **kwargs,
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code >= 500 and self._contains_sql_error(exc.response.text):
                    return self._finding(payload, url, exc.response.text, "Sunucu hata verdi.")
                continue
            except httpx.RequestError:
                continue

            if response.status_code >= 500 and self._contains_sql_error(response.text):
                return self._finding(payload, url, response.text, "Sunucu hata döndürdü.")

            if self._contains_sql_error(response.text):
                return self._finding(payload, url, response.text, "Yanıtta SQL hata izi bulundu.")
        return None

    def _build_payload(self, request_kwargs: Dict[str, Any], payload: str) -> Dict[str, Any]:
        kwargs = deepcopy(request_kwargs)
        params = kwargs.get("params") or {}
        if isinstance(params, dict):
            if params:
                first_key = next(iter(params))
                params[first_key] = payload
            else:
                params["probe"] = payload
            kwargs["params"] = params

        json_body = kwargs.get("json")
        if isinstance(json_body, dict):
            first_key = next(iter(json_body), None)
            if first_key:
                json_body[first_key] = payload
            else:
                json_body["probe"] = payload
            kwargs["json"] = json_body

        data_body = kwargs.get("data")
        if isinstance(data_body, dict):
            first_key = next(iter(data_body), None)
            if first_key:
                data_body[first_key] = payload
            else:
                data_body["probe"] = payload
            kwargs["data"] = data_body

        if not params and "json" not in kwargs and "data" not in kwargs:
            kwargs["params"] = {"probe": payload}
        return kwargs

    @staticmethod
    def _contains_sql_error(body: str) -> bool:
        return any(re.search(pattern, body, re.IGNORECASE) for pattern in SQL_ERRORS)

    def _finding(self, payload: str, url: str, body: str, note: str) -> ScanFinding:
        return ScanFinding(
            check_id=self.check_id,
            severity=self.severity,
            endpoint=url,
            summary="SQL Injection belirtisi tespit edildi",
            description=(
                f"Sunucu, enjekte edilen payload'a hatalı yanıt verdi. {note} "
                "Bu durum parametrik sorgular kullanılmadığına işaret eder."
            ),
            evidence={
                "payload": payload,
                "response_snippet": body[:500],
            },
            remediation="Parametreleri parametrik sorgularla kullanın ve giriş doğrulaması uygulayın.",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        )


