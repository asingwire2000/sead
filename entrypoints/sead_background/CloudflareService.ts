import ApiService from './api-service';
import { StorageService } from './storage-service';
import { RiskState } from './types';

//test url https://nrsinfo.nrscall.gov.au/geoinfo.html
export class CloudflareService extends ApiService {
    private static readonly CACHE_KEY_PREFIX = 'cloudflareRiskCache:';
    private static readonly API_URL = 'https://api.cloudflare.com/client/v4/threat-intel/url-reputation';
    private static readonly CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

    // ⚠️ You must define your token securely
    private readonly apiToken: string;

    constructor(token: string) {
        super();
        this.apiToken = token;
    }

    public async checkUrl(url: string): Promise<RiskState> {
        const cacheKey = CloudflareService.CACHE_KEY_PREFIX + url;
        const cached = await this.getCachedApiResponse(url, 'cloudflare');
        if (cached) return cached;

        try {
            const result = await this.queryCloudflareApi(url);
            await this.cacheApiResponse(url, 'cloudflare', result);
            return result;
        } catch (error) {
            console.error('[Cloudflare] Error checking URL:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async queryCloudflareApi(url: string): Promise<RiskState> {
        try {
            const response = await fetch(CloudflareService.API_URL, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiToken}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            if (!response.ok) throw new Error(`Cloudflare API failed: ${response.status}`);

            const data = await response.json();

            if (data.result?.malicious === true) return 'Phishing';
            if (data.result?.suspicious === true) return 'Suspicious';

            return 'Safe'; // Optional; you can use 'Unknown' if you prefer

        } catch (error) {
            console.error('[Cloudflare] API request failed:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }
}
