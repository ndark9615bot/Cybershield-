import os
import ipaddress
import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request

app = Flask(__name__)
FRONTEND_ORIGIN = "https://ndark9615bot.github.io"


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response
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
def analyze_url_risk(url):
    """Identify common warning signs in a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    warnings = []
    score = 0

    # 1. Flag unusually long URLs.
    if len(url) > 100:
        warnings.append("Unusually long URL")
        score += 1

    # 2. Flag IP addresses used as the hostname.
    try:
        ipaddress.ip_address(hostname)
        warnings.append("URL uses an IP address instead of a domain")
        score += 2
    except ValueError:
        pass

    # 3. Check for suspicious URL terms.
    suspicious_words = [
        "verify", "signin", "login", "account",
        "password", "confirm", "secure"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if len(found_words) >= 2:
        warnings.append("Multiple security-related keywords in URL")
        score += 1

    # 4. Flag insecure HTTP.
    if parsed.scheme == "http":
        warnings.append("URL does not use HTTPS")
        score += 1

    # 5. Flag unusually many subdomains.
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

        result = response.json( "risk_analysis": risk_analysis,)
        risk_analysis = analyze_url_risk(url)
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
            "threats": [ "risk_analysis": risk_analysis,]
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
