/**
 * PhishGuard - Background Service Worker
 * Monitors URLs and scans them for phishing threats
 */

// Configuration
const API_URL = "http://localhost:5000/predict"; // Change to your API server
const CACHE_EXPIRATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
const MIN_URL_LENGTH = 10; // Don't check very short URLs

// Cache for URL check results
let urlCache = {};

function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);

    // Remove 'www.' if present
    let hostname = urlObj.hostname;
    if (hostname.startsWith("www.")) {
      hostname = hostname.substring(4);
    }

    // Extract protocol (http or https)
    let protocol = urlObj.protocol;

    // Reconstruct URL in the format used during training
    // Note: Legitimate URLs in the dataset use http://, not https://
    // Example: http://google.com (no trailing slash)
    let path = urlObj.pathname;
    if (path === "/") {
      path = ""; // Remove trailing slash
    }

    return `${protocol}//${hostname}${path}${urlObj.search}`;
  } catch (error) {
    console.error("Error normalizing URL:", error);
    return url;
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard extension installed");

  // Initialize settings
  chrome.storage.local.get(["settings"], (result) => {
    if (!result.settings) {
      const defaultSettings = {
        enabled: true,
        notificationsEnabled: true,
        blockHighRisk: true,
        riskThreshold: 80, // 0-100 scale
        lastUpdated: Date.now(),
      };
      chrome.storage.local.set({ settings: defaultSettings });
    }
  });

  // Initialize stats
  chrome.storage.local.get(["stats"], (result) => {
    if (!result.stats) {
      const initialStats = {
        urlsChecked: 0,
        phishingDetected: 0,
        blocked: 0,
        lastReset: Date.now(),
      };
      chrome.storage.local.set({ stats: initialStats });
    }
  });
});

// Listen for navigation events
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only process main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;

  // Check settings before proceeding
  chrome.storage.local.get(["settings"], (result) => {
    if (!result.settings || !result.settings.enabled) return;

    // Check the URL
    checkUrl(url, details.tabId);
  });
});

// Update extension icon based on current tab URL
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    updateIcon(tab.url, activeInfo.tabId);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    updateIcon(tab.url, tabId);
  }
});

/**
 * Check if URL is potentially phishing
 * @param {string} url - URL to check
 * @param {number} tabId - Tab ID where URL is being accessed
 */
async function checkUrl(url, tabId) {
  // Ignore non-HTTP URLs, very short URLs, and browser pages
  if (!isValidUrl(url)) {
    return;
  }

  try {
    // Check cache first
    const cachedResult = checkUrlCache(url);
    if (cachedResult) {
      handleResult(cachedResult, url, tabId);
      return;
    }

    // Send request to API
    url = normalizeUrl(url);
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      console.error(`API error: ${response.status}`);
      return;
    }

    const result = await response.json();

    // Cache the result
    cacheUrlResult(url, result);

    // Handle the result
    handleResult(result, url, tabId);

    // Update stats
    updateStats(result);
  } catch (error) {
    console.error("Error checking URL:", error);
  }
}

/**
 * Handle the phishing check result
 * @param {Object} result - API response
 * @param {string} url - The URL that was checked
 * @param {number} tabId - Tab ID
 */
function handleResult(result, url, tabId) {
  chrome.storage.local.get(["settings"], (data) => {
    const settings = data.settings || {};

    // Update icon
    if (result.is_phishing) {
      chrome.action.setIcon({
        path: {
          16: "images/icon16_warning.png",
          48: "images/icon48_warning.png",
          128: "images/icon128_warning.png",
        },
        tabId: tabId,
      });

      // Show notification if enabled
      if (settings.notificationsEnabled) {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "images/icon128_warning.png",
          title: "Phishing Alert!",
          message: `The site ${
            new URL(url).hostname
          } appears to be a phishing site (${result.risk_score.toFixed(
            1
          )}% risk).`,
          priority: 2,
        });
      }

      // Block high-risk sites if enabled
      if (
        settings.blockHighRisk &&
        result.risk_score >= settings.riskThreshold
      ) {
        // Redirect to warning page
        chrome.tabs.update(tabId, {
          url: `warning.html?url=${encodeURIComponent(
            url
          )}&risk=${result.risk_score.toFixed(1)}`,
        });

        // Update blocked count
        chrome.storage.local.get(["stats"], (data) => {
          const stats = data.stats || {};
          stats.blocked = (stats.blocked || 0) + 1;
          chrome.storage.local.set({ stats });
        });
      }
    } else {
      // Safe URL
      chrome.action.setIcon({
        path: {
          16: "images/icon16.png",
          48: "images/icon48.png",
          128: "images/icon128.png",
        },
        tabId: tabId,
      });
    }
  });
}

/**
 * Update extension icon based on URL status
 * @param {string} url - Current URL
 * @param {number} tabId - Tab ID
 */
function updateIcon(url, tabId) {
  if (!isValidUrl(url)) {
    // Default icon for internal pages
    chrome.action.setIcon({
      path: {
        16: "images/icon16.png",
        48: "images/icon48.png",
        128: "images/icon128.png",
      },
      tabId: tabId,
    });
    return;
  }

  const cachedResult = checkUrlCache(url);
  if (cachedResult) {
    // We already have a result for this URL
    if (cachedResult.is_phishing) {
      chrome.action.setIcon({
        path: {
          16: "images/icon16_warning.png",
          48: "images/icon48_warning.png",
          128: "images/icon128_warning.png",
        },
        tabId: tabId,
      });
    } else {
      chrome.action.setIcon({
        path: {
          16: "images/icon16.png",
          48: "images/icon48.png",
          128: "images/icon128.png",
        },
        tabId: tabId,
      });
    }
  } else {
    // Check the URL
    checkUrl(url, tabId);
  }
}

/**
 * Check if URL is in cache
 * @param {string} url - URL to check
 * @returns {Object|null} - Cached result or null
 */
function checkUrlCache(url) {
  const cachedItem = urlCache[url];

  if (!cachedItem) return null;

  // Check if cache is still valid
  if (Date.now() - cachedItem.timestamp > CACHE_EXPIRATION) {
    delete urlCache[url];
    return null;
  }

  return cachedItem.result;
}

/**
 * Store URL check result in cache
 * @param {string} url - URL that was checked
 * @param {Object} result - API result
 */
function cacheUrlResult(url, result) {
  urlCache[url] = {
    result: result,
    timestamp: Date.now(),
  };

  // Cleanup cache if it gets too large
  const cacheSize = Object.keys(urlCache).length;
  if (cacheSize > 1000) {
    cleanupCache();
  }
}

/**
 * Clean up old items from the cache
 */
function cleanupCache() {
  const now = Date.now();

  // Remove expired items
  Object.keys(urlCache).forEach((url) => {
    if (now - urlCache[url].timestamp > CACHE_EXPIRATION) {
      delete urlCache[url];
    }
  });

  // If still too many items, remove oldest
  const cacheSize = Object.keys(urlCache).length;
  if (cacheSize > 800) {
    const sortedUrls = Object.keys(urlCache).sort(
      (a, b) => urlCache[a].timestamp - urlCache[b].timestamp
    );

    // Remove oldest 300 items
    sortedUrls.slice(0, 300).forEach((url) => {
      delete urlCache[url];
    });
  }
}

/**
 * Update usage statistics
 * @param {Object} result - API result
 */
function updateStats(result) {
  chrome.storage.local.get(["stats"], (data) => {
    const stats = data.stats || {};

    stats.urlsChecked = (stats.urlsChecked || 0) + 1;

    if (result.is_phishing) {
      stats.phishingDetected = (stats.phishingDetected || 0) + 1;
    }

    chrome.storage.local.set({ stats });
  });
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

    // Ignore very short URLs
    if (url.length < MIN_URL_LENGTH) {
      return false;
    }

    return true;
  } catch (e) {
    // Invalid URL
    return false;
  }
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkCurrentUrl") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        checkUrl(tabs[0].url, tabs[0].id);
        sendResponse({ status: "checking" });
      } else {
        sendResponse({ status: "error", message: "No active tab found" });
      }
    });
    return true; // Keep channel open for async response
  }

  if (message.action === "getStats") {
    chrome.storage.local.get(["stats"], (data) => {
      sendResponse({ stats: data.stats || {} });
    });
    return true; // Keep channel open for async response
  }

  if (message.action === "resetStats") {
    const initialStats = {
      urlsChecked: 0,
      phishingDetected: 0,
      blocked: 0,
      lastReset: Date.now(),
    };
    chrome.storage.local.set({ stats: initialStats }, () => {
      sendResponse({ status: "success" });
    });
    return true; // Keep channel open for async response
  }

  if (message.action === "getSettings") {
    chrome.storage.local.get(["settings"], (data) => {
      sendResponse({ settings: data.settings || {} });
    });
    return true; // Keep channel open for async response
  }

  if (message.action === "updateSettings") {
    chrome.storage.local.set({ settings: message.settings }, () => {
      sendResponse({ status: "success" });
    });
    return true; // Keep channel open for async response
  }
});
