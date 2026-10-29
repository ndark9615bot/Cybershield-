"use strict";

// ========================================
// CyberShield Configuration
// ========================================

const API_BASE_URL = "https://cybershield-vq90.onrender.com";
const SCAN_API_URL = API_BASE_URL + "/scan";

const HISTORY_KEY = "cybershieldHistory";
const MAX_HISTORY = 50;

// ========================================
// Scan History Storage
// ========================================

function getHistory() {
    try {
        const data = localStorage.getItem(HISTORY_KEY);
        const history = data ? JSON.parse(data) : [];
        return Array.isArray(history) ? history : [];
    } catch (error) {
        console.error("Could not read scan history:", error);
        return [];
    }
}

function saveScan(scan) {
    try {
        const history = getHistory();
        history.unshift(scan);

        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(history.slice(0, MAX_HISTORY))
        );
    } catch (error) {
        console.error("Could not save scan history:", error);
    }

    updateDashboard();
    displayHistory();
}

// ========================================
// Display Messages Safely
// ========================================

function showMessage(container, message, level) {
    container.replaceChildren();

    const box = document.createElement("div");
    box.className = "result-box";

    const paragraph = document.createElement("p");
    paragraph.className = level ? "risk-" + level : "";
    paragraph.textContent = message;

    box.appendChild(paragraph);
    container.appendChild(box);
}

// ========================================
// URL Security Scanner
// ========================================

async function scanURLWithAPI(value) {
    const result = document.getElementById("scanResult");
    const button = document.getElementById("scanButton");

    const rawURL = value.trim();

    let parsedURL;

    try {
        parsedURL = new URL(rawURL);
    } catch (error) {
        showMessage(
            result,
            "Enter a valid URL, such as https://example.com.",
            "medium"
        );
        return;
    }

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
        showMessage(
            result,
            "Only HTTP and HTTPS URLs are supported.",
            "medium"
        );
        return;
    }

    if (parsedURL.username || parsedURL.password) {
        showMessage(
            result,
            "URLs containing embedded usernames or passwords are not accepted.",
            "medium"
        );
        return;
    }

    if (button) {
        button.disabled = true;
        button.textContent = "Scanning...";
    }

    showMessage(result, "Checking URL with Google Safe Browsing...", "");

    try {
        const response = await fetch(SCAN_API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: parsedURL.href
            })
        });

        let data;

        try {
            data = await response.json();
        } catch (error) {
            throw new Error("The server returned an invalid response.");
        }

        if (!response.ok) {
            throw new Error(data.error || "The URL scan failed.");
        }

        // Read risk analysis supplied by the Flask backend.
const warnings = Array.isArray(data.warnings)
    ? data.warnings
    : [];

const rawScore = Number(data.risk_score);

const riskScore = Number.isFinite(rawScore)
    ? Math.max(0, Math.min(100, rawScore))
    : 0;

const rawLevel = String(data.risk_level || "").toLowerCase();

let riskLevel = ["low", "medium", "high"].includes(rawLevel)
    ? rawLevel
    : "low";

if (isUnsafe) {
    riskLevel = "high";
}
        // Build the result display.
        result.replaceChildren();

        const box = document.createElement("div");
        box.className = "result-box";

        const heading = document.createElement("h3");
        heading.className = isUnsafe
            ? "risk-high"
            : "risk-" + riskLevel;

        heading.textContent = isUnsafe
            ? "POTENTIAL THREAT DETECTED"
            : "NO KNOWN THREAT FOUND";

        const safeBrowsingMessage = document.createElement("p");
        safeBrowsingMessage.textContent = data.message ||
            "Google Safe Browsing check completed.";

        const riskHeading = document.createElement("h4");
        riskHeading.textContent = "URL Risk Analysis";

        const levelParagraph = document.createElement("p");
        levelParagraph.textContent =
            "Risk level: " + riskLevel.toUpperCase();

        const scoreParagraph = document.createElement("p");
        scoreParagraph.textContent =
            "Heuristic risk score: " + riskScore;

        box.append(
            heading,
            safeBrowsingMessage,
            riskHeading,
            levelParagraph,
            scoreParagraph
        );

        const warningHeading = document.createElement("h4");
        warningHeading.textContent = "Warning Signs";
        box.appendChild(warningHeading);

        if (warnings.length > 0) {
            const warningList = document.createElement("ul");

            warnings.forEach(warning => {
                const item = document.createElement("li");
                item.textContent = String(warning);
                warningList.appendChild(item);
            });

            box.appendChild(warningList);
        } else {
            const noWarnings = document.createElement("p");
            noWarnings.textContent =
                "No warning signs were detected by the basic URL checks.";
            box.appendChild(noWarnings);
        }

        // Show Safe Browsing threat details, if any.
        if (Array.isArray(data.threats) && data.threats.length > 0) {
            const threatHeading = document.createElement("h4");
            threatHeading.textContent = "Detected Threats";
            box.appendChild(threatHeading);

            const threatList = document.createElement("ul");

            data.threats.forEach(threat => {
                const item = document.createElement("li");

                item.textContent =
                    "Threat: " + (threat.type || "Unknown") +
                    " | Platform: " + (threat.platform || "Unknown");

                threatList.appendChild(item);
            });

            box.appendChild(threatList);
        }

        const notice = document.createElement("p");
        notice.className = "notice";
        notice.textContent =
            "Important: No scan can guarantee a website is safe. " +
            "Risk scores are basic indicators, not proof of malicious activity.";

        box.appendChild(notice);
        result.appendChild(box);

        // Save the scan and update the dashboard/history.
        saveScan({
            url: parsedURL.href,
            score: isUnsafe ? Math.max(100, riskScore) : riskScore,
            level: riskLevel,
            source: "Google Safe Browsing + URL Risk Analysis",
            date: new Date().toLocaleString(),
            warnings: warnings
        });

    } catch (error) {
        console.error("CyberShield scan error:", error);

        showMessage(
            result,
            "Scan failed: " + error.message +
            " Check the backend URL, internet connection, and server logs.",
            "high"
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Scan URL";
        }
    }
}

// ========================================
// Password Strength Checker
// ========================================

function checkPassword(password) {
    const result = document.getElementById("passwordResult");

    result.replaceChildren();

    if (!password) {
        showMessage(result, "Enter a test password first.", "medium");
        return;
    }

    let score = 0;

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    let message;
    let level;

    if (password.length < 8 || score <= 2) {
        message = "Weak — use a longer, less predictable password.";
        level = "high";
    } else if (password.length >= 12 && score >= 4) {
        message = "Stronger by these basic checks. Avoid reusing passwords.";
        level = "low";
    } else {
        message = "Moderate — consider making it longer and less predictable.";
        level = "medium";
    }

    showMessage(result, message, level);
}

// ========================================
// Security Dashboard
// ========================================

function updateDashboard() {
    const history = getHistory();

    const total = history.length;
    const high = history.filter(
        scan => scan.level === "high"
    ).length;
    const medium = history.filter(
        scan => scan.level === "medium"
    ).length;
    const low = history.filter(
        scan => scan.level === "low"
    ).length;

    document.getElementById("totalScans").textContent = total;
    document.getElementById("highScans").textContent = high;
    document.getElementById("mediumScans").textContent = medium;
    document.getElementById("lowScans").textContent = low;

    document.getElementById("dashboardMessage").textContent =
        total === 0
            ? "Scan a URL to start building your dashboard."
            : "Statistics are based on saved URL scan results, not a guarantee of safety.";
}

// ========================================
// Scan History
// ========================================

function displayHistory() {
    const container = document.getElementById("historyList");
    const history = getHistory();

    container.replaceChildren();

    if (history.length === 0) {
        container.textContent = "No scans recorded yet.";
        return;
    }

    history.forEach(scan => {
        const card = document.createElement("div");
        card.className = "history-item";

        const address = document.createElement("p");
        address.textContent = "URL: " + scan.url;

        const level = document.createElement("p");
        level.textContent =
            "Category: " + String(scan.level || "unknown").toUpperCase();

        const source = document.createElement("p");
        source.textContent = "Scan type: " + (scan.source || "URL scan");

        const date = document.createElement("p");
        date.textContent = "Scanned: " + scan.date;

        card.append(address, level, source, date);

        if (Array.isArray(scan.warnings) && scan.warnings.length > 0) {
            const warning = document.createElement("p");
            warning.textContent =
                "Warnings: " + scan.warnings.join(", ");
            card.appendChild(warning);
        }

        container.appendChild(card);
    });
}

// ========================================
// Clear History
// ========================================

function clearHistory() {
    if (!confirm("Clear all saved URL scan history?")) {
        return;
    }

    try {
        localStorage.removeItem(HISTORY_KEY);
    } catch (error) {
        console.error("Could not clear history:", error);
    }

    updateDashboard();
    displayHistory();
}

// ========================================
// Connect Forms
// ========================================

document.getElementById("urlForm").addEventListener(
    "submit",
    function(event) {
        event.preventDefault();

        const input = document.getElementById("urlInput");
        scanURLWithAPI(input.value);
    }
);

document.getElementById("passwordForm").addEventListener(
    "submit",
    function(event) {
        event.preventDefault();

        const input = document.getElementById("passwordInput");
        checkPassword(input.value);

        // Clear the test password from the input.
        input.value = "";
    }
);

document.getElementById("clearHistory").addEventListener(
    "click",
    clearHistory
);

// ========================================
// Start CyberShield
// ========================================

updateDashboard();
displayHistory();

console.log("CyberShield initialized successfully.");
