import ApiService from "./api-service";
import { RiskState } from "./types";


export class VirusTotalService extends ApiService {
  private static readonly API_URL = 'https://www.virustotal.com/api/v3/urls';
  private apiKey: string;

  constructor(apiKey: string) {
    super();
    this.apiKey = apiKey;
  }

  public async checkUrl(url: string): Promise<RiskState> {
    if (!this.apiKey) {
      console.error('VirusTotal API key is missing');
      return 'Unknown';
    }

    const cachedResult = await this.getCachedApiResponse(url, 'virusTotal');
    if (cachedResult) return cachedResult;

    try {
      const result = await this.retryApiCall(() => this.checkUrlReputation(url));
      await this.cacheApiResponse(url, 'virusTotal', result);
      return result;
    } catch (error) {
      console.error('Error checking VirusTotal:', error instanceof Error ? error.message : String(error));
      return 'Unknown';
    }
  }

  private async checkUrlReputation(url: string): Promise<RiskState> {
    // First submit URL for analysis if needed
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    const analysisUrl = `${VirusTotalService.API_URL}/${urlId}`;

    // Check existing analysis
    const response = await this.fetchWithTimeout(analysisUrl, {
      method: 'GET',
      headers: { 'x-apikey': this.apiKey }
    }, 5000);

    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats;

    if (!stats) return 'Unknown';

    if (stats.malicious > 0 || stats.suspicious > 0) {
      return 'Phishing';
    }
    if (stats.unknown > 5) {
      return 'Suspicious';
    }
    return 'Safe';
  }
}