import os
import ipaddress
import re
import requests

from urllib.parse import urlparse
from flask import Flask, jsonify, request

app = Flask(__name__)

FRONTEND_ORIGIN = "https://ndark9615bot.github.io"

GOOGLE_API_KEY = os.environ.get(
    "GOOGLE_SAFE_BROWSING_API_KEY", ""
)

GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

REQUEST_TIMEOUT = 10


# ========================================
# CORS Configuration
# ========================================

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = (
        FRONTEND_ORIGIN
    )
    response.headers["Access-Control-Allow-Methods"] = (
        "POST, OPTIONS"
    )
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type"
    )
    return response


# ========================================
# Home and Health Endpoints
# ========================================

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


# ========================================
# URL Validation
# ========================================

def validate_url(value):
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    if len(value) > 2048:
        return None

    try:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            return None

        if not parsed.hostname:
            return None

        if parsed.username or parsed.password:
            return None

        # Reject malformed ports.
        _ = parsed.port

        hostname = parsed.hostname.rstrip(".").lower()

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            # Basic domain-format validation.
            if "." not in hostname:
                return None

            if any(not part for part in hostname.split(".")):
                return None

            if not re.fullmatch(
                r"[a-z0-9.-]+",
                hostname
            ):
                return None

        return value

    except (ValueError, TypeError):
        return None


# ========================================
# Local URL Risk Analysis
# ========================================

def analyze_url_risk(url):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    warnings = []
    score = 0

    # 1. HTTP instead of HTTPS.
    if parsed.scheme == "http":
        warnings.append(
            "The URL uses HTTP instead of encrypted HTTPS."
        )
        score += 15

    # 2. URL uses an IP address.
    try:
        ipaddress.ip_address(hostname)
        warnings.append(
            "The website uses an IP address as its hostname."
        )
        score += 25
    except ValueError:
        pass

    # 3. Unusually long URL.
    if len(url) > 100:
        warnings.append("The URL is unusually long.")
        score += 10

    # 4. Suspicious words.
    suspicious_words = [
        "verify",
        "signin",
        "login",
        "account",
        "password",
        "confirm",
        "wallet",
        "banking",
        "recover"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if len(found_words) >= 2:
        warnings.append(
            "The URL contains multiple security-related keywords."
        )
        score += 15
    elif len(found_words) == 1:
        warnings.append(
            "The URL contains a security-related keyword."
        )
        score += 5

    # 5. Many subdomains.
    if len(hostname.split(".")) >= 5:
        warnings.append(
            "The hostname contains many domain segments."
        )
        score += 15

    # 6. '@' in URL.
    if "@" in url:
        warnings.append(
            "The URL contains an @ symbol that may be misleading."
        )
        score += 15

    # 7. Punycode domain.
    if "xn--" in hostname:
        warnings.append(
            "The hostname contains encoded international characters."
        )
        score += 15

    # Limit score to 100.
    score = min(score, 100)

    if score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings
    }


# ========================================
# Google Safe Browsing Check
# ========================================

def check_google_safe_browsing(url):
    if not GOOGLE_API_KEY:
        return {
            "available": False,
            "status": "unavailable",
            "threats": [],
            "message": (
                "Google Safe Browsing API key is not configured."
            )
        }

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

            return {
                "available": False,
                "status": "unavailable",
                "threats": [],
                "message": (
                    "Google Safe Browsing could not complete "
                    "the check. Verify API configuration."
                )
            }

        result = response.json()
        matches = result.get("matches", [])

        threats = [
            {
                "type": item.get("threatType", "UNKNOWN"),
                "platform": item.get(
                    "platformType", "UNKNOWN"
                )
            }
            for item in matches
        ]

        return {
            "available": True,
            "status": "unsafe" if threats else "no_known_threat_found",
            "threats": threats,
            "message": (
                "Google Safe Browsing detected a potential threat."
                if threats
                else
                "Google Safe Browsing found no known threat."
            )
        }

    except requests.Timeout:
        return {
            "available": False,
            "status": "unavailable",
            "threats": [],
            "message": "Google Safe Browsing check timed out."
        }

    except (requests.RequestException, ValueError):
        app.logger.exception(
            "Google Safe Browsing request failed"
        )

        return {
            "available": False,
            "status": "unavailable",
            "threats": [],
            "message": (
                "Could not complete the Google Safe Browsing check."
            )
        }


# ========================================
# Main URL Scanner
# ========================================

@app.route("/scan", methods=["POST", "OPTIONS"])
def scan_url():

    # Handle browser CORS preflight requests.
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}
    url = validate_url(data.get("url"))

    if not url:
        return jsonify({
            "error": "Enter a valid HTTP or HTTPS URL."
        }), 400

    # Analyze suspicious URL patterns.
    local_result = analyze_url_risk(url)

    # Check Google's known-threat database.
    google_result = check_google_safe_browsing(url)

    # Combine both results.
    if google_result["status"] == "unsafe":
        final_level = "high"
        final_score = max(
            local_result["risk_score"], 80
        )
        final_status = "unsafe"

    else:
        final_score = local_result["risk_score"]
        final_level = local_result["risk_level"]

        if final_level == "high":
            final_status = "suspicious"
        else:
            final_status = google_result["status"]

    all_warnings = list(local_result["warnings"])

    if google_result["status"] == "unsafe":
        all_warnings.append(
            "Google Safe Browsing reported a known threat."
        )

    return jsonify({
        "url": url,
        "status": final_status,
        "risk_score": final_score,
        "risk_level": final_level,
        "warnings": all_warnings,
        "message": (
            "A known threat was detected."
            if google_result["status"] == "unsafe"
            else
            "URL risk analysis completed. Review the warnings "
            "and Google Safe Browsing result."
        ),
        "google_safe_browsing": {
            "available": google_result["available"],
            "status": google_result["status"],
            "message": google_result["message"],
            "threats": google_result["threats"]
        },
        "notice": (
            "Risk scores are estimates, not proof of malicious "
            "activity. A low score does not guarantee safety."
        )
    })


# ========================================
# Start Application
# ========================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
