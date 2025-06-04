import {
  ABUSEIPDB_API_KEY,
  CLOUDFLARE_API_KEY,
  GOOGLE_SAFE_BROWSING_API_KEY,
  PHISHSTATS_API_KEY,
  VIRUSTOTAL_API_KEY,
} from "./sead_background/api-keys";
import { SecurityAnalyzer } from "./sead_background/security-analyzers";
import { StorageService } from "./sead_background/storage-service";
import { ApiConfig } from "./sead_background/types";
import { browser } from "#imports";

function initializeBackground() {
  console.log("Initializing background service worker...", { id: browser.runtime.id });

  const apiConfig: ApiConfig = {
    googleSafeBrowsingApiKey: GOOGLE_SAFE_BROWSING_API_KEY,
    virusTotalApiKey: VIRUSTOTAL_API_KEY,
    abuseIpdbApiKey: ABUSEIPDB_API_KEY,
    phishStatsApiKey: PHISHSTATS_API_KEY,
    cloudFlareApiKey: CLOUDFLARE_API_KEY,
  };

  const securityAnalyzer = new SecurityAnalyzer(apiConfig);

  const analyzeIfValid = async (url: string, tabId: number) => {
    if (url && url.startsWith("http")) {
      try {
        await securityAnalyzer.analyzeUrl(url, tabId);
      } catch (error) {
        console.error("Analysis failed:", error);
      }
    }
  };

  const messageHandler = async (
    message: any,
    sender: Browser.runtime.MessageSender
  ): Promise<any> => {
    switch (message.action) {
      case "clearCacheAndHistoryForUrl":
        try {
          await Promise.all([
            StorageService.clearCacheForUrl(message.url),
            StorageService.clearHistoryForUrl(message.url),
          ]);
          return { success: true };
        } catch (error) {
          return { success: false, error };
        }

      case "cancelAnalysis":
        securityAnalyzer.cancelAnalysis();
        return { success: true };

      case "refreshAnalysis":
        try {
          console.log(`Analyzing ${message.url}`)
          analyzeIfValid(message.url, message.tabId)
          return { success: true };
        }
        catch (error) {
          return { success: false, error };
        }

      case "saveAppSettings":
        try {
          StorageService.saveSettings(message.settings);
          return { success: true }
        } catch (error) {
          return { success: false, error };
        }


      default:
        console.warn("Unknown action:", message.action);
        return { success: false, error: "Unknown action" };
    }
  };

  const handleTabUpdate = (
    tabId: number,
    changeInfo: Browser.tabs.TabChangeInfo,
    tab: Browser.tabs.Tab
  ) => {
    if (changeInfo.url) {
      analyzeIfValid(changeInfo.url, tabId);
    }
  };

  const handleHistoryStateUpdate = (details: Browser.webNavigation.WebNavigationFramedCallbackDetails) => {
    if (details.frameId === 0) {
      analyzeIfValid(details.url, details.tabId);
    }
  };

  browser.runtime.onMessage.addListener(messageHandler);
  browser.tabs.onUpdated.addListener(handleTabUpdate);
  browser.webNavigation.onHistoryStateUpdated.addListener(handleHistoryStateUpdate);

  return () => {
    browser.runtime.onMessage.removeListener(messageHandler);
    browser.tabs.onUpdated.removeListener(handleTabUpdate);
    browser.webNavigation.onHistoryStateUpdated.removeListener(handleHistoryStateUpdate);
  };
}

export default defineBackground(() => {
  try {
    const cleanup = initializeBackground();
    browser.runtime.onSuspend.addListener(() => {
      cleanup();
      console.log("Service worker shutting down...");
    });
  } catch (err) {
    console.error(err);
  }
});
