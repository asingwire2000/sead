// API Keys - Replace these placeholders with your actual API keys
const GOOGLE_SAFE_BROWSING_API_KEY = ""; // Get from Google Cloud Console: https://console.cloud.google.com/
const VIRUSTOTAL_API_KEY = ""; // Get from VirusTotal: https://www.virustotal.com/gui/join-us
const ABUSEIPDB_API_KEY = ""; // Get from AbuseIPDB: https://www.abuseipdb.com/register
const PHISHSTATS_API_KEY = "your_phishstats_api_key_here"; // Get from PhishStats: https://phishstats.info/ (optional, if replacing PhishTank)

// API URLs
const GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";
const VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls";
const ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check";
const URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/";
const OPENPHISH_API_URL = "https://openphish.com/feed.txt";
const PHISHTANK_DATABASE_URL = "https://data.phishtank.com/data/online-valid.json"; // No API key needed
const PHISHSTATS_API_URL = "https://phishstats.info:2096/api/phishing"; // Used if replacing PhishTank

// Local storage keys
const PHISHTANK_DB_KEY = "phishTankDatabase";
const PHISHTANK_DB_TIMESTAMP_KEY = "phishTankDbTimestamp";
const API_CACHE_KEY = "apiCache";

// Global variable to track cancellation
let cancelAnalysis = false;

// Function to fetch with timeout
async function fetchWithTimeout(url, options, timeout = 5000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    console.log(`Fetching URL: ${url}`); // Debug log
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    console.error(`Fetch error for ${url}:`, error.message); // Debug log
    throw error;
  }
}

// Function to retry with a single attempt
async function retryApiCall(fn, maxRetries = 1) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) {
        console.error(`Failed after ${maxRetries} retries:`, error.message);
        throw error;
      }
      console.log(`Retrying after 1 second... (Attempt ${i + 1}/${maxRetries})`); // Debug log
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

// Cache API responses
async function getCachedApiResponse(url, source) {
  return new Promise(resolve => {
    chrome.storage.local.get([API_CACHE_KEY], (result) => {
      const apiCache = result[API_CACHE_KEY] || {};
      const cacheEntry = apiCache[`${url}:${source}`];
      if (cacheEntry) {
        const cacheAge = Date.now() - cacheEntry.timestamp;
        const cacheExpiration = 24 * 60 * 60 * 1000;
        if (cacheAge < cacheExpiration) {
          console.log(`Using cached response for ${source} on ${url}`); // Debug log
          resolve(cacheEntry.result);
        } else {
          delete apiCache[`${url}:${source}`];
          chrome.storage.local.set({ [API_CACHE_KEY]: apiCache }, () => resolve(null));
        }
      } else {
        resolve(null);
      }
    });
  });
}

async function cacheApiResponse(url, source, result) {
  return new Promise(resolve => {
    chrome.storage.local.get([API_CACHE_KEY], (result) => {
      let apiCache = result[API_CACHE_KEY] || {};
      apiCache[`${url}:${source}`] = { result, timestamp: Date.now() };
      const cacheEntries = Object.entries(apiCache);
      if (cacheEntries.length > 500) {
        apiCache = Object.fromEntries(cacheEntries.slice(0, 500));
      }
      chrome.storage.local.set({ [API_CACHE_KEY]: apiCache }, () => {
        console.log(`Cached response for ${source} on ${url}`); // Debug log
        resolve();
      });
    });
  });
}

// PhishTank database functions
async function fetchPhishTankDatabase() {
  try {
    console.log("Fetching PhishTank database..."); // Debug log
    const response = await fetchWithTimeout(PHISHTANK_DATABASE_URL, {}, 5000);
    const data = await response.json();
    
    const urlIndex = {};
    data.forEach(item => {
      urlIndex[item.url] = item;
    });

    await new Promise((resolve, reject) => {
      chrome.storage.local.set({
        [PHISHTANK_DB_KEY]: urlIndex,
        [PHISHTANK_DB_TIMESTAMP_KEY]: Date.now()
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to save PhishTank database:", chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
        } else {
          console.log("PhishTank database updated successfully");
          resolve();
        }
      });
    });
  } catch (error) {
    console.error("Error fetching PhishTank database:", error.message);
    throw error;
  }
}

async function shouldUpdatePhishTankDatabase() {
  return new Promise((resolve) => {
    chrome.storage.local.get([PHISHTANK_DB_TIMESTAMP_KEY], (result) => {
      const lastUpdate = result[PHISHTANK_DB_TIMESTAMP_KEY] || 0;
      const oneDay = 24 * 60 * 60 * 1000;
      const needsUpdate = Date.now() - lastUpdate > oneDay;
      console.log(`PhishTank database update needed: ${needsUpdate}`); // Debug log
      resolve(needsUpdate);
    });
  });
}

async function checkUrlWithPhishTank(url) {
  const cachedResult = await getCachedApiResponse(url, "phishTank");
  if (cachedResult) return cachedResult;

  try {
    if (await shouldUpdatePhishTankDatabase()) {
      await fetchPhishTankDatabase();
    }

    const urlIndex = await new Promise((resolve) => {
      chrome.storage.local.get([PHISHTANK_DB_KEY], (result) => {
        resolve(result[PHISHTANK_DB_KEY] || {});
      });
    });

    const entry = urlIndex[url];
    const result = entry ? (entry.valid ? "Phishing" : "Suspicious") : "Safe";
    await cacheApiResponse(url, "phishTank", result);
    return result;
  } catch (error) {
    console.error("Error checking PhishTank database:", error.message);
    return "Unknown";
  }
}

// PhishStats (alternative to PhishTank, commented out since API key is not set)
async function checkUrlWithPhishStats(url) {
  if (!PHISHSTATS_API_KEY || PHISHSTATS_API_KEY === "your_phishstats_api_key_here") {
    console.error("PhishStats API key is missing or invalid.");
    return "Unknown";
  }

  const cachedResult = await getCachedApiResponse(url, "phishStats");
  if (cachedResult) return cachedResult;

  try {
    const response = await fetchWithTimeout(`${PHISHSTATS_API_URL}?url=${encodeURIComponent(url)}`, {
      headers: { "Authorization": `Bearer ${PHISHSTATS_API_KEY}` }
    }, 5000);
    const data = await response.json();
    const result = data.results && data.results.length > 0 ? "Phishing" : "Safe";
    await cacheApiResponse(url, "phishStats", result);
    return result;
  } catch (error) {
    console.error("Error querying PhishStats:", error.message);
    return "Unknown";
  }
}

async function checkUrlWithGoogleSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY || GOOGLE_SAFE_BROWSING_API_KEY === "your_google_safe_browsing_api_key_here") {
    console.error("Google Safe Browsing API key is missing or invalid.");
    return "Unknown";
  }

  const cachedResult = await getCachedApiResponse(url, "googleSafeBrowsing");
  if (cachedResult) return cachedResult;

  try {
    const requestBody = {
      client: { clientId: "sead-extension", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    const response = await fetchWithTimeout(`${GOOGLE_SAFE_BROWSING_API_URL}${GOOGLE_SAFE_BROWSING_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    }, 5000);
    const data = await response.json();

    let result;
    if (data.matches) {
      const threatTypes = data.matches.map(match => match.threatType);
      if (threatTypes.includes("SOCIAL_ENGINEERING")) {
        result = "Phishing";
      } else if (threatTypes.includes("MALWARE") || threatTypes.includes("UNWANTED_SOFTWARE") || threatTypes.includes("POTENTIALLY_HARMFUL_APPLICATION")) {
        result = "Suspicious";
      } else {
        result = "Safe";
      }
    } else {
      result = "Safe";
    }
    await cacheApiResponse(url, "googleSafeBrowsing", result);
    return result;
  } catch (error) {
    console.error("Error querying Google Safe Browsing:", error.message);
    return "Unknown";
  }
}

async function checkUrlWithOpenPhish(url) {
  const cachedResult = await getCachedApiResponse(url, "openPhish");
  if (cachedResult) return cachedResult;

  try {
    const response = await fetchWithTimeout(OPENPHISH_API_URL, {}, 5000);
    const text = await response.text();
    const phishingUrls = text.split("\n").filter(line => line.trim() !== "");
    const result = phishingUrls.includes(url) ? "Phishing" : "Safe";
    await cacheApiResponse(url, "openPhish", result);
    return result;
  } catch (error) {
    console.error("Error querying OpenPhish:", error.message);
    return "Unknown";
  }
}

async function checkUrlWithUrlHaus(url) {
  const cachedResult = await getCachedApiResponse(url, "urlHaus");
  if (cachedResult) return cachedResult;

  try {
    const response = await fetchWithTimeout(URLHAUS_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    }, 5000);
    const data = await response.json();
    let result;
    if (data.query_status === "ok" && data.url_status === "online") {
      result = "Phishing";
    } else if (data.query_status === "ok" && data.url_status === "offline") {
      result = "Suspicious";
    } else {
      result = "Safe";
    }
    await cacheApiResponse(url, "urlHaus", result);
    return result;
  } catch (error) {
    console.error("Error querying URLhaus:", error.message);
    return "Unknown";
  }
}

async function checkIpWithAbuseIpDb(url) {
  if (!ABUSEIPDB_API_KEY || ABUSEIPDB_API_KEY === "your_abuseipdb_api_key_here") {
    console.error("AbuseIPDB API key is missing or invalid.");
    return "Unknown";
  }

  const cachedResult = await getCachedApiResponse(url, "abuseIpDb");
  if (cachedResult) return cachedResult;

  try {
    const hostname = new URL(url).hostname;
    const ipResponse = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
    const ipData = await ipResponse.json();
    const ip = ipData.Answer?.[0]?.data;
    if (!ip) {
      console.log(`No IP resolved for ${hostname}`); // Debug log
      return "Unknown";
    }

    const response = await fetchWithTimeout(`${ABUSEIPDB_API_URL}?ipAddress=${ip}&maxAgeInDays=90`, {
      method: "GET",
      headers: { "Key": ABUSEIPDB_API_KEY, "Accept": "application/json" }
    }, 5000);
    const data = await response.json();
    const abuseConfidenceScore = data.data?.abuseConfidenceScore || 0;
    let result;
    if (abuseConfidenceScore > 75) {
      result = "Phishing";
    } else if (abuseConfidenceScore > 25) {
      result = "Suspicious";
    } else {
      result = "Safe";
    }
    await cacheApiResponse(url, "abuseIpDb", result);
    return result;
  } catch (error) {
    console.error("Error querying AbuseIPDB:", error.message);
    return "Unknown";
  }
}

async function checkIpReputation(url) {
  if (!VIRUSTOTAL_API_KEY || VIRUSTOTAL_API_KEY === "your_virustotal_api_key_here") {
    console.error("VirusTotal API key is missing or invalid.");
    return "Unknown";
  }

  const cachedResult = await getCachedApiResponse(url, "ipReputation");
  if (cachedResult) return cachedResult;

  try {
    const urlId = btoa(url).replace(/=/g, "");
    const response = await fetchWithTimeout(`${VIRUSTOTAL_API_URL}/${urlId}`, {
      method: "GET",
      headers: { "x-apikey": VIRUSTOTAL_API_KEY }
    }, 5000);
    const data = await response.json();

    const analysis = data.data.attributes.last_analysis_stats;
    let result;
    if (analysis.malicious > 0 || analysis.suspicious > 0) {
      result = "Phishing";
    } else if (analysis.unknown > 5) {
      result = "Suspicious";
    } else {
      result = "Safe";
    }
    await cacheApiResponse(url, "ipReputation", result);
    return result;
  } catch (error) {
    console.error("Error querying VirusTotal:", error.message);
    return "Unknown";
  }
}

async function heuristicAnalysis(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const suspiciousKeywords = ["login", "signin", "verify", "account", "secure", "update", "password", "bank", "paypal", "amazon"];
    const suspiciousPatterns = [
      /http:\/\/[^/]+\/[^?]+\.php\?/, // Common phishing URL pattern
      /[^\w\d\-]\d{4,}[^\w\d\-]/,    // Suspicious use of numbers
      /[^/]+\.[^/]+\.[^/]+/          // Multiple subdomains
    ];

    const hasSuspiciousKeyword = suspiciousKeywords.some(keyword => hostname.includes(keyword));
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => pattern.test(url));

    if (hasSuspiciousKeyword || hasSuspiciousPattern) {
      return "Suspicious";
    }
    return "Safe";
  } catch (error) {
    console.error("Error in heuristic analysis:", error.message);
    return "Unknown";
  }
}

async function checkHttpsAndSsl(url) {
  try {
    if (!url.startsWith("https://")) {
      return "Suspicious";
    }

    const hostname = new URL(url).hostname;
    const response = await fetch(`https://${hostname}`, { method: "HEAD" });
    const certificateInfo = response.headers.get("Certificate-Info");
    if (!certificateInfo) {
      return "Suspicious";
    }
    return "Safe";
  } catch (error) {
    console.error("Error checking HTTPS/SSL:", error.message);
    return "Suspicious";
  }
}

function combineRiskStates(states) {
  if (states.includes("Phishing")) return "Phishing";
  if (states.includes("Suspicious")) return "Suspicious";
  if (states.every(state => state === "Safe")) return "Safe";
  return "Unknown";
}

function getImpactMessage(state) {
  switch (state) {
    case "Phishing":
      return "High impact: Likely a phishing site. Avoid entering personal information! 😱";
    case "Suspicious":
      return "Moderate impact: This site may be risky. Proceed with caution. 😟";
    case "Safe":
      return "Low impact: This site appears safe. Keep smiling! 😊";
    default:
      return "Unknown impact: Unable to determine the risk. Stay vigilant. 🤔";
  }
}

function calculateVulnerabilityScore(sources) {
  const baseWeights = {
    phishTank: 0.20, // Using PhishTank since PhishStats key is not set
    // phishStats: 0.20,
    googleSafeBrowsing: 0.20,
    openPhish: 0.15,
    urlHaus: 0.15,
    abuseIpDb: 0.10,
    heuristic: 0.10,
    ssl: 0.10,
    ipReputation: 0.10
  };

  const stateScores = {
    Phishing: 100,
    Suspicious: 50,
    Safe: 0,
    Unknown: 25
  };

  let mostSevereState = "Safe";
  let reportingSource = null;
  const sourceStates = Object.entries(sources);
  for (const [source, state] of sourceStates) {
    if (state === "Phishing") {
      mostSevereState = "Phishing";
      reportingSource = source;
      break;
    } else if (state === "Suspicious" && mostSevereState !== "Phishing") {
      mostSevereState = "Suspicious";
      reportingSource = source;
    }
  }

  const adjustedWeights = { ...baseWeights };
  if (reportingSource) {
    adjustedWeights[reportingSource] += 0.20;
    const otherSources = Object.keys(adjustedWeights).filter(s => s !== reportingSource);
    const totalReduction = 0.20 / otherSources.length;
    for (const source of otherSources) {
      adjustedWeights[source] -= totalReduction;
    }
  }

  let score = 0;
  for (const [source, state] of sourceStates) {
    score += (stateScores[state] || 0) * adjustedWeights[source];
  }

  return {
    score: Math.round(score),
    reportingSource: reportingSource || "None"
  };
}

function setBadge(state, tabId) {
  let color, text;
  switch (state) {
    case "Phishing":
      color = "#ff0000";
      text = "RISK";
      break;
    case "Suspicious":
      color = "#ffa500";
      text = "WARN";
      break;
    case "Safe":
      color = "#008000";
      text = "SAFE";
      break;
    default:
      color = "#808080";
      text = "UNKN";
      break;
  }

  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

async function clearCacheForUrl(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["urlCache"], (result) => {
      let cache = result.urlCache || {};
      if (cache[url]) {
        delete cache[url];
        chrome.storage.local.set({ urlCache: cache }, () => {
          console.log(`Cache cleared for URL: ${url}`);
          resolve();
        });
      } else {
        resolve();
      }
    });
  });
}

async function clearHistoryForUrl(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["linkHistory"], (result) => {
      let linkHistory = result.linkHistory || [];
      linkHistory = linkHistory.filter(entry => entry.url !== url);
      chrome.storage.local.set({ linkHistory: linkHistory }, () => {
        console.log(`History cleared for URL: ${url}`);
        resolve();
      });
    });
  });
}

// Listen for messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "clearCacheAndHistoryForUrl") {
    Promise.all([
      clearCacheForUrl(message.url),
      clearHistoryForUrl(message.url)
    ]).then(() => {
      sendResponse({ success: true });
    });
    return true;
  } else if (message.action === "cancelAnalysis") {
    cancelAnalysis = true;
    sendResponse({ success: true });
    return true;
  }
});

chrome.webNavigation.onCompleted.addListener(async (details) => {
  const url = details.url;
  const tabId = details.tabId;

  console.log(`Navigating to URL: ${url}`); // Debug log
  if (!url.startsWith("http")) {
    console.log(`Skipping non-HTTP URL: ${url}`);
    return;
  }

  await clearCacheForUrl(url);
  chrome.runtime.sendMessage({ action: "analysisStarted" });

  let combinedState, impact, sources = {}, vulnerabilityScore, reportingSource, errors = [];
  const totalChecks = 8;
  let completedChecks = 0;

  const updateProgress = () => {
    completedChecks++;
    const progress = Math.round((completedChecks / totalChecks) * 100);
    chrome.runtime.sendMessage({ action: "progressUpdate", progress });
    console.log(`Progress: ${progress}% (${completedChecks}/${totalChecks} checks completed)`); // Debug log
  };

  const startTime = performance.now();

  // Fast checks (heuristic, HTTPS/SSL)
  const fastChecks = [
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting heuristic analysis..."); // Debug log
      const result = await Promise.resolve(heuristicAnalysis(url));
      sources.heuristic = result;
      updateProgress();
    })().catch(err => { errors.push(`Heuristic: ${err.message}`); sources.heuristic = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting HTTPS/SSL check..."); // Debug log
      const result = await retryApiCall(() => checkHttpsAndSsl(url));
      sources.ssl = result;
      updateProgress();
    })().catch(err => { errors.push(`HTTPS/SSL: ${err.message}`); sources.ssl = "Suspicious"; updateProgress(); })
  ];

  try {
    await Promise.all(fastChecks);
  } catch (error) {
    console.error("Error in fast checks:", error.message); // Debug log
  }

  // Interim results after fast checks
  let interimSources = { heuristic: sources.heuristic, ssl: sources.ssl };
  let interimCombinedState = combineRiskStates([sources.heuristic, sources.ssl]);
  let interimScoreResult = calculateVulnerabilityScore(interimSources);
  let interimVulnerabilityScore = interimScoreResult.score;
  let interimReportingSource = interimScoreResult.reportingSource;
  let interimImpact = getImpactMessage(interimCombinedState);

  await new Promise((resolve, reject) => {
    chrome.storage.local.get(["linkHistory"], (result) => {
      let linkHistory = result.linkHistory || [];
      
      linkHistory.unshift({
        url: url,
        state: interimCombinedState,
        impact: interimImpact,
        sources: interimSources,
        vulnerabilityScore: interimVulnerabilityScore,
        reportingSource: interimReportingSource,
        errors: errors,
        timestamp: new Date().toISOString(),
        analysisTime: performance.now() - startTime,
        isInterim: true
      });

      linkHistory = linkHistory.slice(0, 50);

      chrome.storage.local.set({ linkHistory: linkHistory }, () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to save interim history:", chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
        } else {
          console.log("Interim history updated successfully");
          resolve();
        }
      });
    });
  });

  chrome.runtime.sendMessage({ action: "historyUpdated" });

  // Slow checks (API-based)
  const slowChecks = [
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting PhishTank check..."); // Debug log
      const result = await retryApiCall(() => checkUrlWithPhishTank(url));
      sources.phishTank = result;
      updateProgress();
    })().catch(err => { errors.push(`PhishTank: ${err.message}`); sources.phishTank = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting Google Safe Browsing check..."); // Debug log
      const result = await retryApiCall(() => checkUrlWithGoogleSafeBrowsing(url));
      sources.googleSafeBrowsing = result;
      updateProgress();
    })().catch(err => { errors.push(`Google Safe Browsing: ${err.message}`); sources.googleSafeBrowsing = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting OpenPhish check..."); // Debug log
      const result = await retryApiCall(() => checkUrlWithOpenPhish(url));
      sources.openPhish = result;
      updateProgress();
    })().catch(err => { errors.push(`OpenPhish: ${err.message}`); sources.openPhish = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting URLhaus check..."); // Debug log
      const result = await retryApiCall(() => checkUrlWithUrlHaus(url));
      sources.urlHaus = result;
      updateProgress();
    })().catch(err => { errors.push(`URLhaus: ${err.message}`); sources.urlHaus = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting AbuseIPDB check..."); // Debug log
      const result = await retryApiCall(() => checkIpWithAbuseIpDb(url));
      sources.abuseIpDb = result;
      updateProgress();
    })().catch(err => { errors.push(`AbuseIPDB: ${err.message}`); sources.abuseIpDb = "Unknown"; updateProgress(); }),
    (async () => {
      if (cancelAnalysis) throw new Error("Analysis cancelled");
      console.log("Starting VirusTotal check..."); // Debug log
      const result = await retryApiCall(() => checkIpReputation(url));
      sources.ipReputation = result;
      updateProgress();
    })().catch(err => { errors.push(`VirusTotal: ${err.message}`); sources.ipReputation = "Unknown"; updateProgress(); })
  ];

  const analysisTimeout = new Promise(resolve => {
    setTimeout(() => resolve("timeout"), 30000);
  });

  try {
    await Promise.race([Promise.all(slowChecks), analysisTimeout]);
  } catch (error) {
    console.error("Error in slow checks:", error.message); // Debug log
  }

  if (cancelAnalysis) {
    errors.push("Analysis was cancelled by the user.");
  }

  // Final results
  if (["phishTank", "googleSafeBrowsing", "openPhish", "urlHaus", "abuseIpDb", "ipReputation"].every(source => sources[source] === "Unknown")) {
    sources = { heuristic: sources.heuristic, ssl: sources.ssl };
    combinedState = combineRiskStates([sources.heuristic, sources.ssl]);
    const scoreResult = calculateVulnerabilityScore(sources);
    vulnerabilityScore = scoreResult.score;
    reportingSource = scoreResult.reportingSource;
    impact = getImpactMessage(combinedState);
    errors.push("All API checks failed or were cancelled. Using heuristic and SSL checks only.");
  } else {
    combinedState = combineRiskStates(Object.values(sources));
    impact = getImpactMessage(combinedState);
    const scoreResult = calculateVulnerabilityScore(sources);
    vulnerabilityScore = scoreResult.score;
    reportingSource = scoreResult.reportingSource;
  }

  const analysisTime = performance.now() - startTime;
  console.log(`Analysis completed in ${analysisTime.toFixed(2)}ms`);

  // Save to cache
  await new Promise((resolve, reject) => {
    chrome.storage.local.get(["urlCache"], (result) => {
      let cache = result.urlCache || {};
      cache[url] = {
        state: combinedState,
        impact: impact,
        sources: sources,
        vulnerabilityScore: vulnerabilityScore,
        reportingSource: reportingSource,
        errors: errors,
        timestamp: Date.now()
      };
      const cacheEntries = Object.entries(cache);
      if (cacheEntries.length > 100) {
        cache = Object.fromEntries(cacheEntries.slice(0, 100));
      }
      chrome.storage.local.set({ urlCache: cache }, () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to save cache:", chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
        } else {
          console.log("Cache updated successfully"); // Debug log
          resolve();
        }
      });
    });
  });

  // Save to history
  await new Promise((resolve, reject) => {
    chrome.storage.local.get(["linkHistory"], (result) => {
      let linkHistory = result.linkHistory || [];
      
      linkHistory = linkHistory.filter(entry => !(entry.url === url && entry.isInterim));

      linkHistory.unshift({
        url: url,
        state: combinedState,
        impact: impact,
        sources: sources,
        vulnerabilityScore: vulnerabilityScore,
        reportingSource: reportingSource,
        errors: errors,
        timestamp: new Date().toISOString(),
        analysisTime: analysisTime
      });

      linkHistory = linkHistory.slice(0, 50);

      chrome.storage.local.set({ linkHistory: linkHistory }, () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to save history:", chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
        } else {
          console.log("History updated successfully:", linkHistory);
          resolve();
        }
      });
    });
  });

  setBadge(combinedState, tabId);
  chrome.runtime.sendMessage({ action: "historyUpdated" });

  cancelAnalysis = false;
});
