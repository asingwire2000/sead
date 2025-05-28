import ApiService from "./api-service";
import { RiskState } from "./types";

export class URLhausService extends ApiService {
  private static readonly API_URL = 'https://urlhaus-api.abuse.ch/v1/url/';
  

  public async checkUrl(url: string): Promise<RiskState> {
    const cachedResult = await this.getCachedApiResponse(url, 'urlHaus');
    if (cachedResult) return cachedResult;

    try {
      const result = await this.retryApiCall(() => this.queryUrlHaus(url));
      await this.cacheApiResponse(url, 'urlHaus', result);
      return result;
    } catch (error) {
      console.error('Error checking URLhaus:', error instanceof Error ? error.message : String(error));
      return 'Unknown';
    }
  }

  private async queryUrlHaus(url: string): Promise<RiskState> {
    const response = await this.fetchWithTimeout(URLhausService.API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    }, 5000);

    console.log(response.json)
    const data = await response.json();
    
    
    if (data.query_status === 'ok') {
      return data.url_status === 'online' ? 'Phishing' : 
             data.url_status === 'offline' ? 'Suspicious' : 'Safe';
    }
    return 'Safe';
  }
}