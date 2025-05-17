document.addEventListener("DOMContentLoaded", () => {
  const blockNavigationToggle = document.getElementById("blockNavigation");
  const currentUrlElement = document.getElementById("currentUrl");
  const progressValueElement = document.getElementById("progressValue");
  const progressBarElement = document.getElementById("progressBar");
  const cancelAnalysisButton = document.getElementById("cancelAnalysis");
  const riskStateElement = document.getElementById("riskState");
  const scoreValueElement = document.getElementById("scoreValue");
  const scoreBarElement = document.getElementById("scoreBar");
  const reportingSourceElement = document.getElementById("reportingSource");
  const sourcesElement = document.getElementById("sources");
  const impactMessageElement = document.getElementById("impactMessage");
  const errorListElement = document.getElementById("errorList");
  const refreshAnalysisButton = document.getElementById("refreshAnalysis");
  const reportPhishingButton = document.getElementById("reportPhishing");
  const historyListElement = document.getElementById("historyList");

  function updateUI(isLoading = false) {
    if (isLoading) {
      historyListElement.classList.add("loading");
      errorListElement.classList.add("loading");
      cancelAnalysisButton.style.display = "block";
    } else {
      historyListElement.classList.remove("loading");
      errorListElement.classList.remove("loading");
      cancelAnalysisButton.style.display = "none";
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentUrl = tabs[0].url;
      currentUrlElement.textContent = `URL: ${currentUrl}`;

      chrome.storage.local.get(["linkHistory"], (result) => {
        const linkHistory = result.linkHistory || [];

        const currentEntry = linkHistory.find((entry) => entry.url === currentUrl);

        errorListElement.innerHTML = "";
        historyListElement.innerHTML = "";

        if (currentEntry) {
          riskStateElement.textContent = `Risk: ${currentEntry.state}`;
          scoreValueElement.textContent = `${currentEntry.vulnerabilityScore}%`;
          scoreBarElement.style.width = `${currentEntry.vulnerabilityScore}%`;
          scoreBarElement.style.backgroundColor = currentEntry.vulnerabilityScore > 75 ? "#ff4d4d" : currentEntry.vulnerabilityScore > 50 ? "#ffa500" : "#4caf50";
          reportingSourceElement.textContent = `Primary Source: ${currentEntry.reportingSource === "None" ? "None" : currentEntry.reportingSource}`;
          sourcesElement.innerHTML = `
            Sources (Contributing to Score):<br>
            PhishTank: ${currentEntry.sources.phishTank}<br>
            Google Safe Browsing: ${currentEntry.sources.googleSafeBrowsing}<br>
            OpenPhish: ${currentEntry.sources.openPhish}<br>
            URLhaus: ${currentEntry.sources.urlHaus}<br>
            AbuseIPDB: ${currentEntry.sources.abuseIpDb}<br>
            Heuristic Analysis: ${currentEntry.sources.heuristic}<br>
            HTTPS/SSL: ${currentEntry.sources.ssl}<br>
            IP Reputation (VirusTotal): ${currentEntry.sources.ipReputation}
          `;
          impactMessageElement.textContent = currentEntry.impact;

          if (currentEntry.errors && currentEntry.errors.length > 0) {
            currentEntry.errors.forEach(error => {
              const li = document.createElement("li");
              li.textContent = error;
              errorListElement.appendChild(li);
            });
          } else {
            const li = document.createElement("li");
            li.textContent = "No errors detected. All checks completed successfully! 😊";
            errorListElement.appendChild(li);
          }
        } else {
          riskStateElement.textContent = "Risk: Not yet analyzed";
          scoreValueElement.textContent = "N/A";
          scoreBarElement.style.width = "0%";
          reportingSourceElement.textContent = "Primary Source: Not yet analyzed";
          sourcesElement.textContent = "Sources: Not yet analyzed";
          impactMessageElement.textContent = "Impact: Please wait for analysis... 😊";
          const li = document.createElement("li");
          li.textContent = isLoading ? "Analysis in progress..." : "Waiting for analysis to complete...";
          errorListElement.appendChild(li);
        }

        if (linkHistory.length === 0) {
          const li = document.createElement("li");
          li.textContent = "No history available yet. Visit some links to see their analysis! 😊";
          historyListElement.appendChild(li);
        } else {
          linkHistory.forEach((entry) => {
            const li = document.createElement("li");
            li.innerHTML = `
              <span>${entry.state}</span> - ${entry.url}<br>
              Vulnerability Score: ${entry.vulnerabilityScore}% (Primary Source: ${entry.reportingSource})<br>
              Sources: PhishTank (${entry.sources.phishTank}), Google Safe Browsing (${entry.sources.googleSafeBrowsing}), OpenPhish (${entry.sources.openPhish}), URLhaus (${entry.sources.urlHaus}), AbuseIPDB (${entry.sources.abuseIpDb}), Heuristic (${entry.sources.heuristic}), HTTPS/SSL (${entry.sources.ssl}), IP Reputation (${entry.sources.ipReputation})<br>
              Impact: ${entry.impact}<br>
              Errors: ${entry.errors?.length > 0 ? entry.errors.join("; ") : "None"}<br>
              Analysis Time: ${(entry.analysisTime / 1000).toFixed(2)} seconds<br>
              Visited: ${new Date(entry.timestamp).toLocaleString()}
            `;
            historyListElement.appendChild(li);
          });
        }
      });
    });
  }

  // Initial UI update with a slight delay to allow analysis to start
  setTimeout(() => updateUI(), 1000);

  chrome.storage.local.get(["blockNavigation"], (result) => {
    blockNavigationToggle.checked = result.blockNavigation || false;
  });

  blockNavigationToggle.addEventListener("change", () => {
    chrome.storage.local.set({ blockNavigation: blockNavigationToggle.checked });
  });

  cancelAnalysisButton.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "cancelAnalysis" }, () => {
      updateUI();
    });
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "analysisStarted") {
      updateUI(true);
      progressValueElement.textContent = "0%";
      progressBarElement.style.width = "0%";
    } else if (message.action === "progressUpdate") {
      progressValueElement.textContent = `${message.progress}%`;
      progressBarElement.style.width = `${message.progress}%`;
    } else if (message.action === "historyUpdated") {
      updateUI();
    }
  });

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentUrl = tabs[0].url;
    refreshAnalysisButton.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "clearCacheAndHistoryForUrl", url: currentUrl }, () => {
        chrome.tabs.reload(tabs[0].id, () => {
          updateUI(true);
        });
      });
    });

    reportPhishingButton.addEventListener("click", () => {
      const phishTankSubmitUrl = `https://www.phishtank.com/add_web_phish.php?url=${encodeURIComponent(currentUrl)}`;
      chrome.tabs.create({ url: phishTankSubmitUrl });
    });
  });
});