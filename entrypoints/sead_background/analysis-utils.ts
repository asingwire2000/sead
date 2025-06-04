import { RiskState, ApiSource, AnalysisResult } from './types';

export class AnalysisUtils {
  /**
   * Combines multiple risk states into a single overall state
   */
  static combineRiskStates(states: RiskState[]): RiskState {
    if (states.includes('Phishing')) return 'Phishing';
    if (states.includes('Suspicious')) return 'Suspicious';
    if (states.every(state => state === 'Safe')) return 'Safe';
    return 'Unknown';
  }

  /**
   * Generates a human-readable impact message based on risk state
   */
  static getImpactMessage(state: RiskState): string {
    const messages: Record<RiskState, string> = {
      Phishing: '🚨 High risk: This appears to be a phishing site. Do not enter any personal information!',
      Suspicious: '⚠️ Caution: This site shows suspicious characteristics. Proceed with extreme caution.',
      Safe: '✅ Safe: This site appears legitimate. No significant risks detected.',
      Unknown: '❓ Unknown: Unable to determine the safety of this site. Exercise caution.'
    };
    return messages[state] ?? messages.Unknown;
  }

  /**
   * Calculates a vulnerability score from source analysis
   */
  static calculateVulnerabilityScore(
    sources: Record<ApiSource, RiskState>
  ): { score: number; reportingSource: string | null } {
    const baseWeights: Record<ApiSource, number> = {
      phishTank: 0.20,
      googleSafeBrowsing: 0.20,
      openPhish: 0.15,
    
      abuseIpDb: 0.10,
      heuristic: 0.10,
      ssl: 0.10,
      ipReputation: 0.10
    };

    const riskPoints: Record<RiskState, number> = {
      Phishing: 100,
      Suspicious: 50,
      Unknown: 25,
      Safe: 0
    };

    // Identify the most severe source
    let maxSeveritySource: ApiSource | null = null;
    let maxSeverityValue = -1;

    for (const [source, state] of Object.entries(sources) as [ApiSource, RiskState][]) {
      const value = riskPoints[state];
      if (value > maxSeverityValue) {
        maxSeverityValue = value;
        maxSeveritySource = source;
      }
    }

    // Clone and adjust weights
    const weights = { ...baseWeights };
    if (maxSeveritySource) {
      weights[maxSeveritySource] += 0.15;

      const remainingSources = Object.keys(weights).filter(s => s !== maxSeveritySource) as ApiSource[];
      const scaleFactor = (1 - weights[maxSeveritySource]) / remainingSources.length;

      for (const source of remainingSources) {
        weights[source] = parseFloat((scaleFactor).toFixed(4));
      }
    }

    // Compute weighted score
    let weightedScore = 0;
    for (const [source, state] of Object.entries(sources) as [ApiSource, RiskState][]) {
      const value = riskPoints[state];
      const weight = weights[source] ?? 0;
      weightedScore += value * weight;
    }

    return {
      score: Math.min(100, Math.round(weightedScore)),
      reportingSource: maxSeveritySource
    };
  }

  /**
   * Sets the browser badge based on risk state
   */
  static setBadge(state: RiskState, tabId: number): void {
    const badgeConfig: Record<RiskState, { text: string; color: string }> = {
      Phishing: { text: 'PHISH', color: '#d32f2f' },
      Suspicious: { text: 'WARN', color: '#ffa000' },
      Safe: { text: 'SAFE', color: '#388e3c' },
      Unknown: { text: 'UNKN', color: '#616161' }
    };

    const { text, color } = badgeConfig[state] ?? badgeConfig.Unknown;
    browser.action.setBadgeText({ text, tabId });
    browser.action.setBadgeBackgroundColor({ color, tabId });
  }

  /**
   * Formats the full analysis report for display
   */
  static formatResults(result: AnalysisResult): string {
    const lines: string[] = [];

    lines.push(`Analysis Results for ${result.url}`);
    lines.push(`Final Verdict: ${result.state} (Score: ${result.vulnerabilityScore})`);
    lines.push(`Impact: ${this.getImpactMessage(result.state)}\n`);
    lines.push('Detailed Findings:');

    for (const [source, state] of Object.entries(result.sources)) {
      lines.push(`- ${source}: ${state}`);
    }

    if (result.errors.length > 0) {
      lines.push('\nErrors Encountered:');
      for (const error of result.errors) {
        lines.push(`- ${error}`);
      }
    }

    lines.push(`\nAnalysis completed in ${result.analysisTime.toFixed(2)}ms`);
    return lines.join('\n');
  }
}
