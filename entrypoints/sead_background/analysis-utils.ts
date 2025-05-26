import { RiskState, ApiSource, AnalysisResult } from './types';

export class AnalysisUtils {
  /**
   * Combines multiple risk states into a single overall state
   * @param states Array of risk states to combine
   * @returns Combined risk state
   */
  static combineRiskStates(states: RiskState[]): RiskState {
    if (states.includes('Phishing')) return 'Phishing';
    if (states.includes('Suspicious')) return 'Suspicious';
    if (states.every(state => state === 'Safe')) return 'Safe';
    return 'Unknown';
  }

  /**
   * Generates a human-readable impact message based on risk state
   * @param state The risk state to generate message for
   * @returns Appropriate impact message
   */
  static getImpactMessage(state: RiskState): string {
    const messages = {
      Phishing: '🚨 High risk: This appears to be a phishing site. Do not enter any personal information!',
      Suspicious: '⚠️ Caution: This site shows suspicious characteristics. Proceed with extreme caution.',
      Safe: '✅ Safe: This site appears legitimate. No significant risks detected.',
      Unknown: '❓ Unknown: Unable to determine the safety of this site. Exercise caution.'
    };
    return messages[state] || messages.Unknown;
  }

  /**
   * Calculates a vulnerability score based on results from all sources
   * @param sources Record of all analysis sources and their results
   * @returns Object containing score (0-100) and reporting source
   */
  static calculateVulnerabilityScore(
    sources: Record<ApiSource, RiskState>
  ): { score: number; reportingSource: string | null } {
    // Weightings for each analysis source
    const weights: Record<ApiSource, number> = {
      phishTank: 0.20,
      googleSafeBrowsing: 0.20,
      openPhish: 0.15,
      urlHaus: 0.15,
      abuseIpDb: 0.10,
      heuristic: 0.10,
      ssl: 0.10,
      ipReputation: 0.10
    };

    // Points for each risk state
    const stateValues: Record<RiskState, number> = {
      Phishing: 100,
      Suspicious: 50,
      Safe: 0,
      Unknown: 25
    };

    let maxSeveritySource: ApiSource | null = null;
    let maxSeverityValue = -1;

    // Calculate weighted score and find the most severe reporting source
    let weightedScore = 0;
    for (const [source, state] of Object.entries(sources) as [ApiSource, RiskState][]) {
      const value = stateValues[state];
      weightedScore += value * weights[source];

      // Track the most severe source
      if (value > maxSeverityValue) {
        maxSeverityValue = value;
        maxSeveritySource = source;
      }
    }

    // Adjust weights to emphasize the most severe finding
    if (maxSeveritySource) {
      weights[maxSeveritySource] += 0.15;
      // Normalize other weights
      const otherSources = Object.keys(weights).filter(s => s !== maxSeveritySource) as ApiSource[];
      for (const source of otherSources) {
        weights[source] *= 0.85;
      }
      // Recalculate with adjusted weights
      weightedScore = 0;
      for (const [source, state] of Object.entries(sources) as [ApiSource, RiskState][]) {
        weightedScore += stateValues[state] * weights[source];
      }
    }

    return {
      score: Math.min(100, Math.round(weightedScore)),
      reportingSource: maxSeveritySource
    };
  }

  /**
   * Sets the browser action badge based on risk state
   * @param state The current risk state
   * @param tabId The tab ID to set the badge on
   */
  static setBadge(state: RiskState, tabId: number): void {
    const badgeConfig = {
      Phishing: { text: 'PHISH', color: '#d32f2f' }, // Red
      Suspicious: { text: 'WARN', color: '#ffa000' }, // Amber
      Safe: { text: 'SAFE', color: '#388e3c' },      // Green
      Unknown: { text: 'UNKN', color: '#616161' }    // Gray
    };

    const { text, color } = badgeConfig[state] || badgeConfig.Unknown;

    browser.action.setBadgeText({ text, tabId });
    browser.action.setBadgeBackgroundColor({ color, tabId });
  }

  /**
   * Formats analysis results for display
   * @param result The analysis results to format
   * @returns Formatted string with all relevant information
   */
  static formatResults(result: AnalysisResult): string {
    let output = `Analysis Results for ${result.url}\n`;
    output += `Final Verdict: ${result.state} (Score: ${result.vulnerabilityScore})\n`;
    output += `Impact: ${this.getImpactMessage(result.state)}\n\n`;
    output += 'Detailed Findings:\n';

    for (const [source, state] of Object.entries(result.sources)) {
      output += `- ${source}: ${state}\n`;
    }

    if (result.errors.length > 0) {
      output += '\nErrors Encountered:\n';
      result.errors.forEach(error => output += `- ${error}\n`);
    }

    output += `\nAnalysis completed in ${result.analysisTime.toFixed(2)}ms`;
    return output;
  }
}