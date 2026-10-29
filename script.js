"use strict";

// ========================================
// CyberShield Configuration
// ========================================

const API_BASE_URL = "https://cybershield-vq9o.onrender.com";
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
// Display Messages
// ========================================

function showMessage(container, message, level) {
container.replaceChildren();

const box = document.createElement("div");
box.className = "result-box";

const text = document.createElement("p");
text.className = level ? "risk-" + level : "";
text.textContent = message;

box.appendChild(text);
container.appendChild(box);

}

// ========================================
// URL Security Scanner
// ========================================

async function scanURLWithAPI(value) {
const input = document.getElementById("urlInput");
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

button.disabled = true;
button.textContent = "Scanning...";

try {
    const response = await fetch(SCAN_API_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: parsedURL.href })
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

    result.replaceChildren();

    const box = document.createElement("div");
    box.className = "result-box";

    const heading = document.createElement("h3");

    const isUnsafe = data.status === "unsafe";

    heading.className = isUnsafe ? "risk-high" : "risk-low";
    heading.textContent = isUnsafe
        ? "POTENTIAL THREAT DETECTED"
        : "NO KNOWN THREAT FOUND";

    const message = document.createElement("p");
    message.textContent = data.message || "Scan completed.";

    box.append(heading, message);

    if (Array.isArray(data.threats) && data.threats.length > 0) {
        const list = document.createElement("ul");

        data.threats.forEach(threat => {
            const item = document.createElement("li");

            item.textContent =
                "Threat: " + (threat.type || "Unknown") +
                " | Platform: " + (threat.platform || "Unknown");

            list.appendChild(item);
        });

        box.appendChild(list);
    }

    const warning = document.createElement("p");
    warning.className = "notice";
    warning.textContent =
        "No scan can guarantee that a website is safe.";

    box.appendChild(warning);
    result.appendChild(box);

    // Store the API scan in browser history.
    const riskLevel = isUnsafe ? "high" : "low";

    saveScan({
        url: parsedURL.href,
        score: isUnsafe ? 100 : 0,
        level: riskLevel,
        source: "Google Safe Browsing",
        date: new Date().toLocaleString()
    });

} catch (error) {
    console.error("CyberShield scan error:", error);

    showMessage(
        result,
        "Scan failed: " + error.message +
        " Check your internet connection and try again.",
        "high"
    );

} finally {
    button.disabled = false;
    button.textContent = "Scan URL";
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
const high = history.filter(scan => scan.level === "high").length;
const medium = history.filter(scan => scan.level === "medium").length;
const low = history.filter(scan => scan.level === "low").length;

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
