from __future__ import annotations

from typing import Dict, Iterable, List, Type

from scanner.checks.base import VulnerabilityCheck
from scanner.checks.broken_auth import BrokenAuthCheck
from scanner.checks.sensitive_data import SensitiveDataExposureCheck
from scanner.checks.sql_injection import SQLInjectionCheck
from scanner.checks.xss import ReflectedXSSCheck


CHECK_REGISTRY: Dict[str, Type[VulnerabilityCheck]] = {
    SQLInjectionCheck.check_id: SQLInjectionCheck,
    ReflectedXSSCheck.check_id: ReflectedXSSCheck,
    BrokenAuthCheck.check_id: BrokenAuthCheck,
    SensitiveDataExposureCheck.check_id: SensitiveDataExposureCheck,
}


def iter_checks(ids: Iterable[str]) -> List[VulnerabilityCheck]:
    instances: List[VulnerabilityCheck] = []
    for check_id in ids:
        cls = CHECK_REGISTRY.get(check_id)
        if not cls:
            continue
        instances.append(cls())
    return instances


def all_checks() -> List[VulnerabilityCheck]:
    return [cls() for cls in CHECK_REGISTRY.values()]


