from __future__ import annotations

import asyncio
from typing import Iterable, List, Optional

from rich.console import Console

from scanner.checks.base import CheckContext, VulnerabilityCheck
from scanner.checks.registry import CHECK_REGISTRY, all_checks, iter_checks
from scanner.core.config import Endpoint, ScannerConfig
from scanner.core.http_client import HttpClient
from scanner.core.reporting import ScanFinding, ScanReport


class Scanner:
    def __init__(self, config: ScannerConfig, max_concurrency: int, console: Console) -> None:
        self.config = config
        self.console = console
        rate_delay = 60 / config.rate_limit_per_minute if config.rate_limit_per_minute else None
        headers = dict(config.iter_headers())
        self.http_client = HttpClient(config.http, headers, rate_delay=rate_delay)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.report = ScanReport()

    async def scan(self) -> ScanReport:
        self.console.print(f"[bold]Tarama başlıyor:[/bold] {self.config.name}")
        tasks = [asyncio.create_task(self._scan_endpoint(endpoint)) for endpoint in self._iter_endpoints()]
        if tasks:
            await asyncio.gather(*tasks)
        else:
            self.report.add_log("Tarama yapılacak endpoint bulunamadı.")
        self.report.summary.total_requests = self.http_client.request_count
        self.report.summary.finalize()
        await self.http_client.close()
        return self.report

    def _iter_endpoints(self) -> Iterable[Endpoint]:
        endpoints = self.config.scope.endpoints
        if not endpoints:
            self.report.add_log("Konfigürasyonda endpoint tanımı yok.")
        return endpoints

    async def _scan_endpoint(self, endpoint: Endpoint) -> None:
        request_kwargs = self._build_request_kwargs(endpoint)
        checks = self._resolve_checks(endpoint)
        if not checks:
            self.report.add_log(f"{endpoint.identifier}: etkin kontrol yok.")
            return

        for check in checks:
            async with self.semaphore:
                finding = await self._run_check(endpoint, check, request_kwargs)
                if finding:
                    self.report.add_finding(finding)

    async def _run_check(
        self,
        endpoint: Endpoint,
        check: VulnerabilityCheck,
        request_kwargs: dict,
    ) -> Optional[ScanFinding]:
        context = CheckContext(
            base_url=str(self.config.scope.base_url),
            endpoint=endpoint.path,
            method=endpoint.method,
            request_kwargs=request_kwargs,
            metadata={
                "endpoint_name": endpoint.name,
                "credentials": [cred.model_dump() for cred in self.config.credentials],
            },
            http_client=self.http_client,
        )

        try:
            result = await check.execute(context)
            if result:
                self.report.add_log(f"{endpoint.identifier} -> {check.check_id} bulgu üretti.")
            return result
        except Exception as exc:  # noqa: BLE001
            self.report.add_log(f"{endpoint.identifier} -> {check.check_id} hata: {exc}")
            return None

    def _resolve_checks(self, endpoint: Endpoint) -> List[VulnerabilityCheck]:
        if endpoint.enabled_checks:
            return iter_checks(endpoint.enabled_checks)
        if self.config.default_checks:
            return iter_checks(self.config.default_checks)
        return all_checks()

    def _build_request_kwargs(self, endpoint: Endpoint) -> dict:
        headers = dict(self.config.iter_headers())
        for header in endpoint.headers:
            headers[header.name] = header.value

        kwargs: dict = {"headers": headers}
        if endpoint.query:
            kwargs["params"] = dict(endpoint.query)
        if endpoint.json:
            kwargs["json"] = dict(endpoint.json)
        if endpoint.data:
            kwargs["data"] = dict(endpoint.data)
        return kwargs


