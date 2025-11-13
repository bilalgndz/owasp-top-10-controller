from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml
from pydantic import BaseModel, Field, HttpUrl, PositiveInt, validator


class AuthCredential(BaseModel):
    username: str
    password: str


class Header(BaseModel):
    name: str
    value: str


class HttpSettings(BaseModel):
    timeout: float = Field(default=10.0, ge=1.0, le=120.0)
    max_retries: PositiveInt = Field(default=2, le=5)
    user_agent: str = Field(
        default="AdvancedVulnScanner/0.1 (+https://example.com/security)"
    )
    verify_ssl: bool = True


class Endpoint(BaseModel):
    name: str
    method: str = Field(default="GET")
    path: str
    description: Optional[str] = None
    enabled_checks: Optional[List[str]] = None
    risk_override: Optional[int] = Field(default=None, ge=0, le=10)
    query: Dict[str, Any] = Field(default_factory=dict)
    json: Dict[str, Any] = Field(default_factory=dict)
    data: Dict[str, Any] = Field(default_factory=dict)
    headers: List[Header] = Field(default_factory=list)

    @validator("method")
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @property
    def identifier(self) -> str:
        return f"{self.method} {self.path}"


class Scope(BaseModel):
    base_url: HttpUrl
    include_paths: List[str] = Field(default_factory=list)
    exclude_paths: List[str] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)

    @validator("endpoints", each_item=True)
    def ensure_leading_slash(cls, endpoint: Endpoint) -> Endpoint:
        if not endpoint.path.startswith("/"):
            endpoint.path = "/" + endpoint.path
        return endpoint


class ScannerConfig(BaseModel):
    name: str
    scope: Scope
    http: HttpSettings = Field(default_factory=HttpSettings)
    default_checks: List[str] = Field(default_factory=list)
    headers: List[Header] = Field(default_factory=list)
    credentials: List[AuthCredential] = Field(default_factory=list)
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=10, le=600)

    def iter_headers(self) -> Iterable[tuple[str, str]]:
        for header in self.headers:
            yield header.name, header.value


def load_scanner_config(path: Path) -> ScannerConfig:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return ScannerConfig.model_validate(data)


