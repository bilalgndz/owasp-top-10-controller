from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.traceback import install as install_rich_traceback

from scanner.core.config import load_scanner_config
from scanner.core.scanner import Scanner


console = Console()
install_rich_traceback(show_locals=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="OWASP Top 10 odaklı web zafiyet tarayıcısı prototipi",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        required=True,
        help="Tarama senaryosu için YAML konfigürasyon dosyası",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Tarama raporunun kaydedileceği yol (JSON)",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=8,
        help="Eş zamanlı istek limiti",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="İstek zaman aşımı (saniye). Yapılandırmada belirtileni ezmek için kullanın.",
    )
    return parser.parse_args()


async def run_scan(config_path: Path, report_path: Optional[Path], max_concurrency: int, timeout: Optional[float]) -> int:
    config = load_scanner_config(config_path)
    if timeout is not None:
        config.http.timeout = timeout

    scanner = Scanner(config=config, max_concurrency=max_concurrency, console=console)
    report = await scanner.scan()

    console.rule("[bold cyan]Tarama Sonuçları")
    report.render(console=console)

    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report.write_json(report_path)
        console.print(f"[green]Rapor kaydedildi:[/green] {report_path}")

    return 0 if report.summary.stats["critical"] == 0 else 1


def app() -> None:
    args = parse_args()
    exit_code = asyncio.run(
        run_scan(
            config_path=args.config,
            report_path=args.report,
            max_concurrency=args.max_concurrency,
            timeout=args.timeout,
        )
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    app()


