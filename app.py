import os
import ipaddress
import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request

app = Flask(__name__)

GOOGLE_API_KEY = os.environ.get(
    "GOOGLE_SAFE_BROWSING_API_KEY", ""
)

GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

REQUEST_TIMEOUT = 10


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "app": "CyberShield Backend",
        "status": "running",
        "message": "CyberShield API is working!"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})


def validate_url(value):
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    try:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            return None

        if not parsed.hostname:
            return None

        if parsed.username or parsed.password:
            return None

        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if "." not in parsed.hostname:
                return None

        return value

    except (ValueError, TypeError):
        return None


@app.route("/scan", methods=["POST", "OPTIONS"])
def scan_url():
    if request.method == "OPTIONS":
        response = app.make_response(("", 204))
        response.headers["Access-Control-Allow-Origin"] = (
            "https://ndark9615bot.github.io"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "POST, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type"
        )
        return response

    data = request.get_json(silent=True) or {}
    url = validate_url(data.get("url"))

    if not url:
        return jsonify({
            "error": "Enter a valid HTTP or HTTPS URL."
        }), 400

    if not GOOGLE_API_KEY:
        return jsonify({
            "error": "Safe Browsing API key is not configured."
        }), 503

    payload = {
        "client": {
            "clientId": "cybershield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            GOOGLE_SAFE_BROWSING_URL,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            app.logger.error(
                "Safe Browsing API returned HTTP %s",
                response.status_code
            )
            return jsonify({
                "error": (
                    "Safe Browsing API request failed. "
                    "Check the API key, API enablement, and restrictions."
                )
            }), 502

        result = response.json()
        matches = result.get("matches", [])

        if matches:
            return jsonify({
                "url": url,
                "status": "unsafe",
                "message": "A potential threat was detected.",
                "threats": [
                    {
                        "type": item.get("threatType", "UNKNOWN"),
                        "platform": item.get(
                            "platformType", "UNKNOWN"
                        )
                    }
                    for item in matches
                ]
            })

        return jsonify({
            "url": url,
            "status": "no_known_threat_found",
            "message": (
                "No known threat was found in the Safe Browsing "
                "check. This does not guarantee the URL is safe."
            ),
            "threats": []
        })

    except requests.Timeout:
        return jsonify({
            "error": "The security check timed out. Try again."
        }), 504

    except requests.RequestException:
        app.logger.exception("Safe Browsing request failed")
        return jsonify({
            "error": "Could not connect to the security-check service."
        }), 502


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
