from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from scanner.core.config import load_scanner_config
from scanner.core.scanner import Scanner
from rich.console import Console

app = Flask(__name__)
CORS(app)

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

console = Console()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Yeni bir tarama başlat"""
    data = request.json
    config_path = data.get("config_path")
    
    if not config_path:
        return jsonify({"error": "config_path gerekli"}), 400
    
    config_file = Path(config_path)
    if not config_file.exists():
        return jsonify({"error": f"Konfigürasyon dosyası bulunamadı: {config_path}"}), 404
    
    # Asenkron taramayı başlat
    import time
    report_id = f"scan_{int(time.time())}"
    report_path = REPORTS_DIR / f"{report_id}.json"
    
    try:
        config = load_scanner_config(config_file)
        scanner = Scanner(config=config, max_concurrency=8, console=console)
        
        # Asenkron fonksiyonu çalıştır
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        report = loop.run_until_complete(scanner.scan())
        
        # Raporu kaydet
        report.write_json(report_path)
        
        return jsonify({
            "success": True,
            "report_id": report_id,
            "summary": report.summary.serialize(),
            "findings_count": len(report.findings)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports")
def list_reports():
    """Tüm raporları listele"""
    reports = []
    for report_file in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
            reports.append({
                "id": report_file.stem,
                "filename": report_file.name,
                "summary": data.get("summary", {}),
                "findings_count": len(data.get("findings", [])),
            })
        except Exception:
            continue
    
    return jsonify({"reports": reports})


@app.route("/api/reports/<report_id>")
def get_report(report_id: str):
    """Belirli bir raporu getir"""
    report_path = REPORTS_DIR / f"{report_id}.json"
    
    if not report_path.exists():
        return jsonify({"error": "Rapor bulunamadı"}), 404
    
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/configs")
def list_configs():
    """Mevcut konfigürasyon dosyalarını listele"""
    configs_dir = Path("configs")
    configs = []
    
    if configs_dir.exists():
        for config_file in configs_dir.glob("*.yaml"):
            configs.append({
                "name": config_file.stem,
                "path": str(config_file),
            })
    
    return jsonify({"configs": configs})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

