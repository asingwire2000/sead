// types.ts
export type RiskState = 'Phishing' | 'Suspicious' | 'Safe' | 'Unknown';
export type ApiSource = 'phishTank' | 'googleSafeBrowsing' | 'openPhish' | 'urlHaus' | 'abuseIpDb' | 'ipReputation' | 'heuristic' | 'ssl';

export interface AnalysisResult {
  url: any;
  state: RiskState;
  impact: string;
  sources: Record<ApiSource, RiskState>;
  vulnerabilityScore: number;
  reportingSource: string | null;
  errors: string[];
  timestamp: string;
  analysisTime: number;
  isInterim?: boolean;
}

export interface CacheEntry {
  state: RiskState;
  impact: string;
  sources: Record<ApiSource, RiskState>;
  vulnerabilityScore: number;
  reportingSource: string | null;
  errors: string[];
  timestamp: number;
}

export interface LinkHistoryEntry extends Omit<AnalysisResult, 'timestamp'> {
  url: string;
  timestamp: string;
  isInterim?: boolean;
}

export interface ApiCacheEntry {
  result: RiskState;
  timestamp: number;
}

export interface ApiCache {
  [key: string]: ApiCacheEntry;
}

export interface PhishTankEntry {
  url: string;
  valid: boolean;
  // Add other fields from PhishTank if needed
}

export interface PhishTankDatabase {
  [url: string]: PhishTankEntry;
}

export interface ApiConfig {
  googleSafeBrowsingApiKey: string;
  virusTotalApiKey: string;
  abuseIpdbApiKey: string;
  phishStatsApiKey: string;
}