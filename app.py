import os
import ipaddress
import requests

from urllib.parse import urlparse
from flask import Flask, jsonify, request

app = Flask(__name__)

# Your GitHub Pages frontend URL
FRONTEND_ORIGIN = "https://ndark9615bot.github.io"

# Google Safe Browsing configuration
GOOGLE_API_KEY = os.environ.get(
    "GOOGLE_SAFE_BROWSING_API_KEY", ""
)

GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

REQUEST_TIMEOUT = 10


# Add CORS headers so the frontend can communicate with this API.
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# Backend home page
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "app": "CyberShield Backend",
        "status": "running",
        "message": "CyberShield API is working!"
    })


# Health check
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy"
    })


# Validate submitted URLs
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


# Analyze common warning signs in a URL.
# This is a heuristic and does not prove that a URL is malicious.
def analyze_url_risk(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    warnings = []
    score = 0

    # Check URL length
    if len(url) > 100:
        warnings.append("Unusually long URL")
        score += 1

    # Check whether the hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        warnings.append(
            "URL uses an IP address instead of a domain"
        )
        score += 2
    except ValueError:
        pass

    # Check suspicious words
    suspicious_words = [
        "verify",
        "signin",
        "login",
        "account",
        "password",
        "confirm",
        "secure"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if len(found_words) >= 2:
        warnings.append(
            "Multiple security-related keywords in URL"
        )
        score += 1

    # Check for insecure HTTP
    if parsed.scheme == "http":
        warnings.append("URL does not use HTTPS")
        score += 1

    # Check for many subdomains
    if len(hostname.split(".")) >= 5:
        warnings.append("Unusually many domain segments")
        score += 1

    if score >= 3:
        level = "high"
    elif score >= 1:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_level": level,
        "risk_score": score,
        "warnings": warnings
    }


# URL scanning endpoint
@app.route("/scan", methods=["POST", "OPTIONS"])
def scan_url():

    # Handle browser CORS preflight requests
    if request.method == "OPTIONS":
        return "", 204

    # Read the submitted URL
    data = request.get_json(silent=True) or {}
    url = validate_url(data.get("url"))

    if not url:
        return jsonify({
            "error": "Enter a valid HTTP or HTTPS URL."
        }), 400

    # Check whether the API key is configured
    if not GOOGLE_API_KEY:
        return jsonify({
            "error": (
                "Safe Browsing API key is not configured."
            )
        }), 503

    # Perform basic local URL risk analysis
    risk_analysis = analyze_url_risk(url)

    # Prepare Google Safe Browsing request
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
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(
            GOOGLE_SAFE_BROWSING_URL,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        # Handle Google API errors
        if response.status_code != 200:
            app.logger.error(
                "Safe Browsing API returned HTTP %s",
                response.status_code
            )

            return jsonify({
                "error": (
                    "Safe Browsing API request failed. "
                    "Check the API key, API enablement, "
                    "and API restrictions."
                )
            }), 502

        # Parse Google's response correctly
        result = response.json()
        matches = result.get("matches", [])

        # Combine Google results with local risk analysis
        if matches:
            status = "unsafe"
            message = (
                "Google Safe Browsing detected a potential threat."
            )

            threats = [
                {
                    "type": item.get(
                        "threatType", "UNKNOWN"
                    ),
                    "platform": item.get(
                        "platformType", "UNKNOWN"
                    )
                }
                for item in matches
            ]

        else:
            status = "no_known_threat_found"
            message = (
                "Google Safe Browsing found no known threat. "
                "This does not guarantee that the URL is safe."
            )

            threats = []

        return jsonify({
            "url": url,
            "status": status,
            "message": message,
            "threats": threats,
            "risk_analysis": risk_analysis
        }), 200

    except requests.Timeout:
        return jsonify({
            "error": (
                "The security check timed out. Please try again."
            )
        }), 504

    except requests.RequestException:
        app.logger.exception(
            "Safe Browsing request failed"
        )

        return jsonify({
            "error": (
                "Could not connect to the security-check service."
            )
        }), 502

    except ValueError:
        app.logger.exception(
            "Could not parse Safe Browsing response"
        )

        return jsonify({
            "error": (
                "The security service returned an invalid response."
            )
        }), 502


# Start the application locally
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(
        host="0.0.0.0",
        port=port
    )
