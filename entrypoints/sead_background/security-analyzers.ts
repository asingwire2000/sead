import { RiskState, ApiSource, AnalysisResult, ApiConfig } from './types';
import { StorageService } from './storage-service';
import { PhishTankService } from './phishtank-service';

import { AbuseIPDBService } from './abuseipdb-service';
import { OpenPhishService } from './openphish-service';
import { URLhausService } from './urlhaus-service';
import { HeuristicAnalyzer } from './heuristic-analyzer';
import { AnalysisUtils } from './analysis-utils';
import GoogleSafeBrowsingService from './googlesafebrowsing-service';
import { IpReputationService } from './ipreputaion-service';

export class SecurityAnalyzer {
  private cancelanalysis: boolean = false;
  private readonly config: ApiConfig;
  private readonly phishTankService: PhishTankService;
  private readonly googleSafeBrowsingService: GoogleSafeBrowsingService;
  private readonly abuseIPDbService: AbuseIPDBService;
  private readonly openPhishService: OpenPhishService;
  private readonly urlHausService: URLhausService;
  private readonly ipReputationService: IpReputationService;

  constructor(config: ApiConfig) {
    this.config = config;
    this.phishTankService = new PhishTankService();
    this.googleSafeBrowsingService = new GoogleSafeBrowsingService(config.googleSafeBrowsingApiKey);
    this.abuseIPDbService = new AbuseIPDBService(config.abuseIpdbApiKey);
    this.openPhishService = new OpenPhishService();
    this.urlHausService = new URLhausService();
    this.ipReputationService = new IpReputationService(config.abuseIpdbApiKey);
  }


  public async analyzeUrl(url: string, tabId: number): Promise<void> {
    try {
      if (!this.isValidHttpUrl(url)) {
        console.log(`Skipping non-HTTP URL: ${url}`);
        return;
      }


      this.cancelanalysis = false;
      console.log(`clearing Cache`);
      await StorageService.clearCacheForUrl(url);
      console.log(`sending messge`);
      await browser.runtime.sendMessage({ action: 'analysisStarted' });
      console.log(`a`);
      console.log(`n`);

      const startTime = performance.now();
      const errors: string[] = [];
      const sources: Partial<Record<ApiSource, RiskState>> = {};
      const totalChecks = 8;
      let completedChecks = 0;
      console.log(`i`);

      const updateProgress = (): void => {
        completedChecks++;
        const progress = Math.round((completedChecks / totalChecks) * 100);
        browser.runtime.sendMessage({ action: 'progressUpdate', progress }).catch(console.error);
      };

      // Fast checks (heuristic, HTTPS/SSL)
      await this.performFastChecks(url, sources, errors, updateProgress);

      // Interim results
      const interimSources = this.getInterimSources(sources);
      const interimResult = this.getInterimResult(interimSources, errors, startTime);

      await StorageService.saveToHistory({
        url,
        ...interimResult,
        isInterim: true
      });

      await browser.runtime.sendMessage({ action: 'historyUpdated' });

      // Slow checks (API-based)
      await this.performSlowChecks(url, sources, errors, updateProgress, startTime);

      if (this.cancelanalysis) {
        errors.push('Analysis was cancelled by the user.');
      }

      // Final results
      const finalResult = this.getFinalResult(sources, errors, startTime);

      // Save to cache and history
      await this.saveResults(url, finalResult);

      AnalysisUtils.setBadge(finalResult.state, tabId);
      await browser.runtime.sendMessage({ action: 'historyUpdated' });
    } catch (error) {
      console.error('Error in analysis:', error);
    } finally {
      this.cancelanalysis = false;
    }
  }

  public cancelAnalysis(): void {
    this.cancelanalysis = true;
  }

  private isValidHttpUrl(url: string): boolean {
    return url.startsWith('http');
  }

  private async performFastChecks(
    url: string,
    sources: Partial<Record<ApiSource, RiskState>>,
    errors: string[],
    updateProgress: () => void
  ): Promise<void> {
    try {
      sources.heuristic = HeuristicAnalyzer.analyze(url);
    } catch (err) {
      errors.push(`Heuristic: ${err instanceof Error ? err.message : String(err)}`);
      sources.heuristic = 'Unknown';
    } finally {
      updateProgress();
    }

    try {
      sources.ssl = await this.retryApiCall(() => HeuristicAnalyzer.checkHttpsAndSsl(url));
    } catch (err) {
      console.log('checking ssl ee')
      errors.push(`HTTPS/SSL: ${err instanceof Error ? err.message : String(err)}`);
      sources.ssl = 'Suspicious';
    } finally {
      updateProgress();
    }
  }

  private getInterimSources(
    sources: Partial<Record<ApiSource, RiskState>>
  ): Record<ApiSource, RiskState> {
    return {
      heuristic: sources.heuristic || 'Unknown',
      ssl: sources.ssl || 'Unknown',
      phishTank: 'Unknown',
      googleSafeBrowsing: 'Unknown',
      openPhish: 'Unknown',
      // urlHaus: 'Unknown',
      abuseIpDb: 'Unknown',
      ipReputation: 'Unknown'
    };
  }

  private getInterimResult(
    sources: Record<ApiSource, RiskState>,
    errors: string[],
    startTime: number
  ): Omit<AnalysisResult, 'url' | 'isInterim'> {
    return {
      state: AnalysisUtils.combineRiskStates(Object.values(sources)),
      impact: AnalysisUtils.getImpactMessage(AnalysisUtils.combineRiskStates(Object.values(sources))),
      sources,
      vulnerabilityScore: AnalysisUtils.calculateVulnerabilityScore(sources).score,
      reportingSource: AnalysisUtils.calculateVulnerabilityScore(sources).reportingSource,
      errors,
      timestamp: new Date().toISOString(),
      analysisTime: performance.now() - startTime
    };
  }

  private async performSlowChecks(
    url: string,
    sources: Partial<Record<ApiSource, RiskState>>,
    errors: string[],
    updateProgress: () => void,
    startTime: number
  ): Promise<void> {
    const slowChecks: Promise<void>[] = [
      this.performCheck('phishTank', () => this.phishTankService.checkUrl(url), sources, errors, updateProgress),
      this.performCheck('googleSafeBrowsing', () => this.googleSafeBrowsingService.checkUrl(url), sources, errors, updateProgress),
      this.performCheck('openPhish', () => this.openPhishService.checkUrl(url), sources, errors, updateProgress),
      //this.performCheck('urlHaus', () => this.urlHausService.checkUrl(url), sources, errors, updateProgress),
      this.performCheck('abuseIpDb', () => this.abuseIPDbService.checkUrl(url), sources, errors, updateProgress),
      this.performCheck('ipReputation', () => this.ipReputationService.checkUrl(url), sources, errors, updateProgress)
    ];

    const analysisTimeout = new Promise<void>((resolve) => {
      setTimeout(() => {
        errors.push('Analysis timed out');
        resolve();
      }, 30000);
    });

    await Promise.race([Promise.all(slowChecks), analysisTimeout]);
  }

  private getFinalResult(
    sources: Partial<Record<ApiSource, RiskState>>,
    errors: string[],
    startTime: number
  ): Omit<AnalysisResult, 'url'> {
    const finalSources = this.getFinalSources(sources, errors);
    const combinedState = AnalysisUtils.combineRiskStates(Object.values(finalSources));
    const scoreResult = AnalysisUtils.calculateVulnerabilityScore(finalSources);

    return {
      state: combinedState,
      impact: AnalysisUtils.getImpactMessage(combinedState),
      sources: finalSources,
      vulnerabilityScore: scoreResult.score,
      reportingSource: scoreResult.reportingSource,
      errors,
      timestamp: new Date().toISOString(),
      analysisTime: performance.now() - startTime
    };
  }

  private getFinalSources(
    sources: Partial<Record<ApiSource, RiskState>>,
    errors: string[]
  ): Record<ApiSource, RiskState> {
    const apiSources: ApiSource[] = ['phishTank', 'googleSafeBrowsing', 'openPhish', 'abuseIpDb']; //'urlHaus',

    if (apiSources.every(source => sources[source] === 'Unknown')) {
      errors.push('All API checks failed or were cancelled. Using heuristic and SSL checks only.');
      return {
        heuristic: sources.heuristic || 'Unknown',
        ssl: sources.ssl || 'Unknown',
        phishTank: 'Unknown',
        googleSafeBrowsing: 'Unknown',
        openPhish: 'Unknown',
        // urlHaus: 'Unknown',
        abuseIpDb: 'Unknown',
        ipReputation: 'Unknown'
      };
    }

    return {
      heuristic: sources.heuristic || 'Unknown',
      ssl: sources.ssl || 'Unknown',
      phishTank: sources.phishTank || 'Unknown',
      googleSafeBrowsing: sources.googleSafeBrowsing || 'Unknown',
      openPhish: sources.openPhish || 'Unknown',
      //  urlHaus: sources.urlHaus || 'Unknown',
      abuseIpDb: sources.abuseIpDb || 'Unknown',
      ipReputation: sources.ipReputation || 'Unknown'
    };
  }

  private async performCheck(
    source: ApiSource,
    checkFn: () => Promise<RiskState>,
    sources: Partial<Record<ApiSource, RiskState>>,
    errors: string[],
    updateProgress: () => void
  ): Promise<void> {
    if (this.cancelanalysis) {
      throw new Error('Analysis cancelled');
    }

    try {
      sources[source] = await this.retryApiCall(checkFn);
    } catch (err) {
      errors.push(`${source}: ${err instanceof Error ? err.message : String(err)}`);
      sources[source] = 'Unknown';
    } finally {
      updateProgress();
    }
  }

  private async retryApiCall<T>(fn: () => Promise<T>, maxRetries = 1): Promise<T> {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === maxRetries - 1) {
          console.error(`Failed after ${maxRetries} retries:`, error instanceof Error ? error.message : String(error));
          throw error;
        }
        console.log(`Retrying after 1 second... (Attempt ${i + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    throw new Error('Unexpected error in retryApiCall');
  }

  private async saveResults(url: string, result: Omit<AnalysisResult, 'url'>): Promise<void> {
    await Promise.all([
      StorageService.saveToCache(url, {
        state: result.state,
        impact: result.impact,
        sources: result.sources,
        vulnerabilityScore: result.vulnerabilityScore,
        reportingSource: result.reportingSource,
        errors: result.errors
      }),
      StorageService.saveToHistory({
        url,
        ...result
      })
    ]);
  }
}