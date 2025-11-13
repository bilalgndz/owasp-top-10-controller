from pathlib import Path

from scanner.core.config import load_scanner_config


def test_load_sample_config(tmp_path: Path) -> None:
    sample = Path("configs/sample_target.yaml")
    config = load_scanner_config(sample)

    assert config.name == "Demo Hedef"
    assert config.scope.base_url == "http://localhost:8000"
    assert config.default_checks == ["SQLI-001", "XSS-001", "DATA-001"]
    assert config.scope.endpoints[0].enabled_checks == ["AUTH-001"]

