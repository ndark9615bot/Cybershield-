import os
import ipaddress
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

Initialize Flask correctly

app = Flask(name)

Read the API key from Render environment variables

GOOGLE_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

GOOGLE_SAFE_BROWSING_URL = (
"https://safebrowsing.googleapis.com/v5alpha1/urls:search"
)

REQUEST_TIMEOUT = 15

==========================================

HOME PAGE

==========================================

@app.route("/", methods=["GET"])
def home():
return jsonify({
"app": "CyberShield Backend",
"status": "running",
"message": "CyberShield API is working!"
})

==========================================

HEALTH CHECK

==========================================

@app.route("/health", methods=["GET"])
def health():
return jsonify({
"status": "healthy"
})

==========================================

URL VALIDATION

==========================================

def validate_url(value):
"""Validate an HTTP or HTTPS URL."""

if not isinstance(value, str):
    return None

value = value.strip()

if not value or len(value) > 2048:
    return None

try:
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return None

    if not parsed.hostname:
        return None

    # Reject URLs containing embedded credentials.
    if parsed.username or parsed.password:
        return None

    # Detect malformed ports.
    try:
        parsed.port
    except ValueError:
        return None

    hostname = parsed.hostname.rstrip(".").lower()

    if not hostname:
        return None

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        # Otherwise, perform basic domain-name validation.
        if hostname != "localhost":
            if "." not in hostname:
                return None

            if any(not label for label in hostname.split(".")):
                return None

            if any(
                not label.replace("-", "").isalnum()
                for label in hostname.split(".")
            ):
                return None

    return parsed.geturl()

except (ValueError, TypeError):
    return None

==========================================

GOOGLE SAFE BROWSING SCANNER

==========================================

@app.route("/scan", methods=["POST"])
def scan_url():

# Confirm that the API key is configured.
if not GOOGLE_API_KEY:
    return jsonify({
        "error": "Google Safe Browsing API key is not configured."
    }), 503

# Read the JSON request.
data = request.get_json(silent=True)

if not isinstance(data, dict):
    return jsonify({
        "error": "Send a JSON request containing a URL."
    }), 400

# Validate the supplied URL.
url = validate_url(data.get("url"))

if not url:
    return jsonify({
        "error": "Enter a valid HTTP or HTTPS URL."
    }), 400

# Safe Browsing v5 urls.search uses repeated urls query parameters.
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

    if response.status_code in (401, 403):
        app.logger.error(
            "Google Safe Browsing authentication or permission failure."
        )

        return jsonify({
            "error": "Google API authentication or permission failed."
        }), 502

    if response.status_code == 400:
        app.logger.error(
            "Google Safe Browsing rejected the request: %s",
            response.text[:500]
        )

        return jsonify({
            "error": "Google rejected the request. Check API configuration."
        }), 502

    if response.status_code == 429:
        return jsonify({
            "error": "Google API rate limit reached. Try again later."
        }), 503

    response.raise_for_status()

    result = response.json()

    # An empty threats list means no match was returned.
    threats = result.get("threats", [])

    if not isinstance(threats, list):
        threats = []

    return jsonify({
        "url": url,
        "checked": True,
        "threat_detected": len(threats) > 0,
        "threats": threats,
        "message": (
            "A threat match was returned by Google Safe Browsing."
            if threats
            else "No threat match was returned by Google Safe Browsing."
        )
    }), 200

except requests.Timeout:
    return jsonify({
        "error": "Google Safe Browsing timed out. Please try again."
    }), 504

except requests.RequestException:
    app.logger.exception("Google Safe Browsing request failed.")

    return jsonify({
        "error": "Could not contact Google Safe Browsing."
    }), 502

except ValueError:
    app.logger.exception("Invalid response from Google Safe Browsing.")

    return jsonify({
        "error": "Google returned an unexpected response."
    }), 502

==========================================

START SERVER

==========================================

if name == "main":
port = int(os.environ.get("PORT", "10000"))

app.run(
    host="0.0.0.0",
    port=port,
    debug=False
)
