
/* =========================================
   1. CONFIGURATION
========================================= */

const API_BASE_URL = "http://127.0.0.1:8000/api";


/* =========================================
   2. GET HTML ELEMENTS
========================================= */

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const loadingState = document.getElementById("loadingState");
const errorMessage = document.getElementById("errorMessage");

const resultSection = document.getElementById("resultSection");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const scannedUrl = document.getElementById("scannedUrl");
const findingsList = document.getElementById("findingsList");

const historyList = document.getElementById("historyList");
const refreshHistory = document.getElementById("refreshHistory");

const threatIntelButton = document.getElementById("threatIntelButton");
const threatIntelResult = document.getElementById("threatIntelResult");


/* =========================================
   3. APPLICATION STATE
========================================= */

let lastScannedUrl = "";


/* =========================================
   4. SHOW AND HIDE MESSAGES
========================================= */

function showError(message) {

    errorMessage.textContent = message;
    errorMessage.classList.remove("hidden");

}

function hideError() {

    errorMessage.textContent = "";
    errorMessage.classList.add("hidden");

}


/* =========================================
   5. LOADING STATE
========================================= */

function setLoading(isLoading) {

    loadingState.classList.toggle("hidden", !isLoading);

    scanButton.disabled = isLoading;

    scanButton.textContent = isLoading
        ? "Scanning..."
        : "Scan URL";

}


/* =========================================
   6. RISK LEVEL STYLING
========================================= */

function getRiskClass(level) {

    const normalizedLevel = level.toLowerCase();

    if (normalizedLevel.includes("high")) {
        return "risk-high";
    }

    if (normalizedLevel.includes("medium")) {
        return "risk-medium";
    }

    return "risk-low";

}


function getRiskColor(level) {

    const normalizedLevel = level.toLowerCase();

    if (normalizedLevel.includes("high")) {
        return "#ef4444";
    }

    if (normalizedLevel.includes("medium")) {
        return "#f59e0b";
    }

    return "#22c55e";

}


/* =========================================
   7. DISPLAY SCAN RESULTS
========================================= */

function displayResults(data) {

    resultSection.classList.remove("hidden");

    riskScore.textContent = data.risk_score;

    riskLevel.textContent = data.risk_level;

    scannedUrl.textContent = data.url;

    const riskColor = getRiskColor(data.risk_level);

    riskScore.style.color = riskColor;
    riskScore.style.borderColor = riskColor;

    riskLevel.style.color = riskColor;

    findingsList.replaceChildren();

    if (!data.findings || data.findings.length === 0) {

        const message = document.createElement("div");

        message.className = "no-findings";

        message.textContent =
            "No suspicious indicators were detected by the local analysis.";

        findingsList.appendChild(message);

        return;

    }

    data.findings.forEach(finding => {

        const item = document.createElement("div");

        item.className = "finding-item";

        const icon = document.createElement("span");

        icon.className = "finding-icon";
        icon.textContent = "⚠️";

        const content = document.createElement("div");

        const title = document.createElement("h4");
        title.textContent = finding.name;

        const description = document.createElement("p");
        description.textContent = finding.description;

        content.appendChild(title);
        content.appendChild(description);

        item.appendChild(icon);
        item.appendChild(content);

        findingsList.appendChild(item);

    });

}


/* =========================================
   8. SCAN URL
========================================= */

scanForm.addEventListener("submit", async (event) => {


    event.preventDefault();

    hideError();

    const url = urlInput.value.trim();

    if (!url) {

        showError("Please enter a website URL.");

        return;

    }

    setLoading(true);

    resultSection.classList.add("hidden");

    threatIntelResult.classList.add("hidden");

    threatIntelButton.disabled = false;

    lastScannedUrl = "";

    try {
        console.log("SENDING SCAN REQUEST:", url);

        const response = await fetch(`${API_BASE_URL}/scan`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail || "Unable to scan this URL."
            );

        }

        lastScannedUrl = data.url;

        displayResults(data);

        await loadHistory();

    }

    catch (error) {

        console.error("Scan error:", error);

        showError(
            error.message.includes("Failed to fetch")
                ? "Cannot connect to the backend. Make sure FastAPI is running."
                : error.message
        );

    }

    finally {

        setLoading(false);

    }

});


/* =========================================
   9. LOAD SCAN HISTORY
========================================= */

async function loadHistory() {

    try {

        const response = await fetch(
            `${API_BASE_URL}/history`
        );

        if (!response.ok) {

            throw new Error("Unable to load scan history.");

        }

        const records = await response.json();

        historyList.replaceChildren();

        if (records.length === 0) {

            const emptyMessage = document.createElement("p");

            emptyMessage.className = "empty-state";

            emptyMessage.textContent = "No scans found yet.";

            historyList.appendChild(emptyMessage);

            return;

        }

        records.forEach(record => {

            const item = document.createElement("div");

            item.className = "history-item";

            const information = document.createElement("div");

            information.style.minWidth = "0";

            const url = document.createElement("div");

            url.className = "history-url";
            url.textContent = record.url;

            const date = document.createElement("div");

            date.className = "history-meta";

            date.textContent = new Date(
                record.created_at
            ).toLocaleString();

            information.appendChild(url);
            information.appendChild(date);

            const badge = document.createElement("span");

            badge.className =
                `risk-badge ${getRiskClass(record.risk_level)}`;

            badge.textContent =
                `${record.risk_level} · ${record.risk_score}/100`;

            item.appendChild(information);
            item.appendChild(badge);

            historyList.appendChild(item);

        });

    }

    catch (error) {

        console.error("History error:", error);

        historyList.textContent =
            "Unable to load scan history. Check the backend connection.";

    }

}


/* =========================================
   10. VIRUSTOTAL THREAT INTELLIGENCE
========================================= */

threatIntelButton.addEventListener("click", async () => {

    if (!lastScannedUrl) {

        showError("Scan a URL before requesting a VirusTotal check.");

        return;

    }

    const confirmed = window.confirm(
        "This will send the URL to VirusTotal for external analysis. " +
        "Do not submit private, confidential, or sensitive URLs. " +
        "Do you want to continue?"
    );

    if (!confirmed) {

        return;

    }

    hideError();

    threatIntelButton.disabled = true;

    threatIntelButton.textContent = "Checking...";

    threatIntelResult.classList.remove("hidden");

    threatIntelResult.textContent =
        "Contacting VirusTotal...";

    try {

        const response = await fetch(
            `${API_BASE_URL}/threat-intel`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: lastScannedUrl
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail || "VirusTotal request failed."
            );

        }

        const heading = document.createElement("strong");

        heading.textContent = "VirusTotal response";

        const output = document.createElement("pre");

        output.style.whiteSpace = "pre-wrap";
        output.style.overflowWrap = "anywhere";
        output.style.marginTop = "12px";

        output.textContent = JSON.stringify(data, null, 2);

        threatIntelResult.replaceChildren(
            heading,
            output
        );

    }

    catch (error) {

        console.error("VirusTotal error:", error);

        threatIntelResult.textContent = error.message;

    }

    finally {

        threatIntelButton.disabled = false;

        threatIntelButton.textContent =
            "Check with VirusTotal";

    }

});


/* =========================================
   11. REFRESH HISTORY
========================================= */

refreshHistory.addEventListener("click", () => {

    loadHistory();

});


/* =========================================
   12. INITIALIZE APPLICATION
========================================= */

document.addEventListener("DOMContentLoaded", () => {

    loadHistory();

});

