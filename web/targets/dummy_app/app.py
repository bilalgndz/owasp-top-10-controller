from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore[attr-defined]


USERS = {
    "admin": "admin123",
    "test": "test123",
}

PRODUCTS = [
    {"id": 1, "name": "Ultra DB Server", "category": "database"},
    {"id": 2, "name": "Security Camera", "category": "hardware"},
    {"id": 3, "name": "Smart Lock", "category": "iot"},
]

COMMENTS: List[Dict[str, str]] = []


@app.route("/api/health")
def health() -> tuple[Dict[str, str], int]:
    return {"status": "ok", "time": datetime.utcnow().isoformat()}, 200


@app.route("/api/login", methods=["POST"])
def login() -> tuple[Dict[str, str], int]:
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if USERS.get(username) == password:
        # intentionally weak token
        return (
            {
                "token": f"{username}-token-123456",
                "message": "Login successful",
            },
            200,
        )

    if "'" in username or "'" in password:
        # simulate SQL error exposed to client
        return (
            {
                "error": "SQL syntax error near '",
                "debug": "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
                % (username, password),
            },
            500,
        )

    return {"error": "Invalid credentials"}, 401


@app.route("/api/products")
def products() -> tuple[Dict[str, List[Dict[str, str]]], int]:
    category = request.args.get("category", "")
    search = request.args.get("search", "")

    items = PRODUCTS
    if category:
        items = [item for item in PRODUCTS if category.lower() in item["category"]]

    if "'" in search:
        # simulate SQL failure to trigger SQLI detection
        return (
            {
                "error": "SQLSTATE[HY000]: General error: unterminated quoted string at or near ",
                "payload": search,
            },
            500,
        )

    response = {"items": items}

    if search == "leak":
        response["debug"] = {
            "aws_key": "AKIAEXAMPLE1234567890",
            "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.signature",
        }

    return response, 200


@app.route("/api/comments", methods=["POST"])
def comments() -> tuple[Dict[str, str], int]:
    data = request.get_json(force=True) or {}
    message = data.get("message", "")
    COMMENTS.append({"message": message})
    # intentionally returns raw message to trigger reflected XSS
    return (
        {"status": "stored", "preview": f"Yorumunuz: {message}"},
        200,
    )


@app.route("/")
def index() -> tuple[Dict[str, str], int]:
    return {
        "message": "Dummy vulnerable API. Endpoints: /api/login, /api/products, /api/comments",
    }, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

