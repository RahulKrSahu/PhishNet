/**
 * PhishGuard - Popup UI Controller
 * Manages the popup interface and interacts with the background service
 */

// DOM Elements
const statusElement = document.getElementById("status");
const urlElement = document.getElementById("current-url");
const riskScoreElement = document.getElementById("risk-score");
const riskMeterElement = document.getElementById("risk-meter");
const riskLevelElement = document.getElementById("risk-level");
const enabledToggle = document.getElementById("enabled-toggle");
const notificationsToggle = document.getElementById("notifications-toggle");
const blockHighRiskToggle = document.getElementById("block-high-risk-toggle");
const riskThresholdSlider = document.getElementById("risk-threshold");
const riskThresholdValue = document.getElementById("risk-threshold-value");
const statsUrlsChecked = document.getElementById("stats-urls-checked");
const statsPhishingDetected = document.getElementById(
  "stats-phishing-detected"
);
const statsBlocked = document.getElementById("stats-blocked");
const resetStatsButton = document.getElementById("reset-stats");
const scanButton = document.getElementById("scan-button");

// Initialize popup
document.addEventListener("DOMContentLoaded", () => {
  // Load settings
  loadSettings();

  // Load current tab info
  loadCurrentTabInfo();

  // Load statistics
  loadStats();

  // Set up event listeners
  setupEventListeners();
});

/**
 * Load user settings from storage
 */
function loadSettings() {
  chrome.runtime.sendMessage({ action: "getSettings" }, (response) => {
    const settings = response.settings || {};

    // Update UI with settings
    enabledToggle.checked = settings.enabled !== false;
    notificationsToggle.checked = settings.notificationsEnabled !== false;
    blockHighRiskToggle.checked = settings.blockHighRisk !== false;

    // Risk threshold slider
    const threshold = settings.riskThreshold || 80;
    riskThresholdSlider.value = threshold;
    riskThresholdValue.textContent = threshold;
  });
}

/**
 * Load information about the current tab
 */
function loadCurrentTabInfo() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) {
      setStatusMessage("No active tab found", "error");
      return;
    }

    const currentTab = tabs[0];
    const url = currentTab.url;

    // Display the URL (truncated if necessary)
    if (url) {
      try {
        const parsedUrl = new URL(url);
        urlElement.textContent = parsedUrl.hostname;
        urlElement.title = url; // Full URL on hover

        // Check if this is a valid URL to scan
        if (!isValidUrl(url)) {
          setStatusMessage("Internal or browser page (not scanned)", "info");
          hideRiskDisplay();
          return;
        }

        // Check if we have a cached result
        checkUrlStatus(url);
      } catch (e) {
        setStatusMessage("Invalid URL", "error");
        hideRiskDisplay();
      }
    } else {
      setStatusMessage("No URL available", "error");
      hideRiskDisplay();
    }
  });
}

/**
 * Check URL phishing status
 * @param {string} url - URL to check
 */
function checkUrlStatus(url) {
  setStatusMessage("Checking URL...", "info");

  // Ask background script for URL status
  chrome.runtime.sendMessage(
    {
      action: "checkCurrentUrl",
    },
    (response) => {
      // The actual result will come from the background script via storage
      // Wait a bit and then check for results
      setTimeout(() => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (!tabs || !tabs[0]) return;
          const tabId = tabs[0].id;

          // Get the current icon to determine status
          chrome.action.getIcon({ tabId: tabId }, (iconInfo) => {
            const iconPath = iconInfo?.path?.[16] || "";
            const isPhishing = iconPath.includes("warning");

            if (isPhishing) {
              // Check storage for detailed risk info
              chrome.storage.local.get([`risk_${url}`], (data) => {
                const riskData = data[`risk_${url}`];
                const riskScore = riskData?.risk_score || 85; // Default high if unknown
                displayRiskScore(riskScore);
                setStatusMessage("Phishing site detected!", "danger");
              });
            } else {
              displayRiskScore(0);
              setStatusMessage("Site appears safe", "success");
            }
          });
        });
      }, 500);
    }
  );
}

/**
 * Display the risk score in the UI
 * @param {number} score - Risk score (0-100)
 */
function displayRiskScore(score) {
  // Update risk meter
  riskScoreElement.textContent = score.toFixed(1);
  riskMeterElement.value = score;

  // Set color and risk level text
  let riskLevel, riskClass;
  if (score >= 80) {
    riskLevel = "High Risk";
    riskClass = "danger";
  } else if (score >= 50) {
    riskLevel = "Medium Risk";
    riskClass = "warning";
  } else if (score >= 20) {
    riskLevel = "Low Risk";
    riskClass = "caution";
  } else {
    riskLevel = "Safe";
    riskClass = "success";
  }

  riskLevelElement.textContent = riskLevel;
  riskLevelElement.className = riskClass;

  // Show risk display section
  document.getElementById("risk-display").style.display = "block";
}

/**
 * Hide the risk display section
 */
function hideRiskDisplay() {
  document.getElementById("risk-display").style.display = "none";
}

/**
 * Set status message in the UI
 * @param {string} message - Status message
 * @param {string} type - Message type (info, success, warning, error, danger)
 */
function setStatusMessage(message, type) {
  statusElement.textContent = message;
  statusElement.className = `status-${type}`;
}

/**
 * Load statistics from storage
 */
function loadStats() {
  chrome.runtime.sendMessage({ action: "getStats" }, (response) => {
    const stats = response.stats || {};

    statsUrlsChecked.textContent = stats.urlsChecked || 0;
    statsPhishingDetected.textContent = stats.phishingDetected || 0;
    statsBlocked.textContent = stats.blocked || 0;

    // Format last reset date if available
    if (stats.lastReset) {
      const resetDate = new Date(stats.lastReset);
      document.getElementById("stats-last-reset").textContent =
        resetDate.toLocaleDateString();
    }
  });
}

/**
 * Set up event listeners for interactive elements
 */
function setupEventListeners() {
  // Toggle switches
  enabledToggle.addEventListener("change", saveSettings);
  notificationsToggle.addEventListener("change", saveSettings);
  blockHighRiskToggle.addEventListener("change", saveSettings);

  // Risk threshold slider
  riskThresholdSlider.addEventListener("input", () => {
    riskThresholdValue.textContent = riskThresholdSlider.value;
  });
  riskThresholdSlider.addEventListener("change", saveSettings);

  // Reset stats button
  resetStatsButton.addEventListener("click", () => {
    if (confirm("Are you sure you want to reset all statistics?")) {
      chrome.runtime.sendMessage({ action: "resetStats" }, () => {
        loadStats(); // Reload stats after reset
        setStatusMessage("Statistics reset successfully", "success");
      });
    }
  });

  // Scan button
  scanButton.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        checkUrlStatus(tabs[0].url);
      }
    });
  });
}

/**
 * Save settings to storage
 */
function saveSettings() {
  const settings = {
    enabled: enabledToggle.checked,
    notificationsEnabled: notificationsToggle.checked,
    blockHighRisk: blockHighRiskToggle.checked,
    riskThreshold: parseInt(riskThresholdSlider.value, 10),
    lastUpdated: Date.now(),
  };

  chrome.runtime.sendMessage(
    {
      action: "updateSettings",
      settings: settings,
    },
    () => {
      setStatusMessage("Settings saved", "success");

      // Settings info fades after a moment
      setTimeout(() => {
        if (statusElement.textContent === "Settings saved") {
          statusElement.textContent = "";
        }
      }, 2000);
    }
  );
}

/**
 * Check if URL should be processed
 * @param {string} url - URL to validate
 * @returns {boolean} - True if URL should be checked
 */
function isValidUrl(url) {
  // Check URL format
  try {
    const parsedUrl = new URL(url);

    // Ignore browser internal pages
    if (
      parsedUrl.protocol === "chrome:" ||
      parsedUrl.protocol === "chrome-extension:" ||
      parsedUrl.protocol === "about:" ||
      parsedUrl.protocol === "edge:" ||
      parsedUrl.protocol === "brave:" ||
      parsedUrl.protocol === "firefox:"
    ) {
      return false;
    }

    // Only process HTTP and HTTPS
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return false;
    }

    return true;
  } catch (e) {
    // Invalid URL
    return false;
  }
}
