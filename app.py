import os
import ipaddress
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(name)

GOOGLE_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
GOOGLE_SAFE_BROWSING_URL = (
"https://safebrowsing.googleapis.com/v5alpha1/urls:search"
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
"""Accept only valid HTTP or HTTPS URLs with a hostname."""
if not isinstance(value, str) or not value or len(value) > 2048:
return None

try:
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return None

    if not parsed.hostname or parsed.username or parsed.password:
        return None

    # Reject malformed ports.
    try:
        parsed.port
    except ValueError:
        return None

    hostname = parsed.hostname.rstrip(".").lower()

    if not hostname:
        return None

    # Accept IP addresses or ordinary DNS-style hostnames.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname and hostname != "localhost":
            return None

        if any(not label for label in hostname.split(".")):
            return None

    return parsed.geturl()

except (ValueError, TypeError):
    return None

@app.route("/scan", methods=["POST"])
def scan_url():
if not GOOGLE_API_KEY:
return jsonify({
"error": "Safe Browsing API key is not configured on the server."
}), 503

data = request.get_json(silent=True)

if not isinstance(data, dict):
    return jsonify({"error": "Send a JSON request body."}), 400

url = validate_url(data.get("url"))

if not url:
    return jsonify({
        "error": "Enter a valid HTTP or HTTPS URL."
    }), 400

params = [
    ("key", GOOGLE_API_KEY),
    ("urls", url)
]

try:
    response = requests.get(
        GOOGLE_SAFE_BROWSING_URL,
        params=params,
        timeout=REQUEST_TIMEOUT
    )

    if response.status_code == 400:
        return jsonify({
            "error": "Google rejected the request. Check the API configuration."
        }), 502

    if response.status_code in (401, 403):
        return jsonify({
            "error": "Google API authentication or permission failed."
        }), 502

    if response.status_code == 429:
        return jsonify({
            "error": "Google API rate limit reached. Try again later."
        }), 503

    response.raise_for_status()
    result = response.json()

    threats = result.get("threats", [])

    return jsonify({
        "url": url,
        "checked": True,
        "threat_detected": len(threats) > 0,
        "threats": threats,
        "message": (
            "Google Safe Browsing reported a threat match."
            if threats
            else "No threat match was returned by Google Safe Browsing."
        )
    })

except requests.Timeout:
    return jsonify({
        "error": "Google Safe Browsing timed out. Please try again."
    }), 504

except requests.RequestException:
    app.logger.exception("Safe Browsing request failed")
    return jsonify({
        "error": "Could not contact Google Safe Browsing."
    }), 502

except ValueError:
    return jsonify({
        "error": "Google returned an unexpected response."
    }), 502

if name == "main":
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
