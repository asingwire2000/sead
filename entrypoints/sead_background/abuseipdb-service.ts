import ApiService from "./api-service";
import { RiskState } from "./types";


export class AbuseIPDBService extends ApiService {
    private static readonly API_URL = 'https://api.abuseipdb.com/api/v2/check';
    private apiKey: string;

    constructor(apiKey: string) {
        super();
        this.apiKey = apiKey;
    }

    public async checkUrl(url: string): Promise<RiskState> {
        if (!this.apiKey) {
            console.error('AbuseIPDB API key is missing');
            return 'Unknown';
        }

        const cachedResult = await this.getCachedApiResponse(url, 'abuseIpDb');
        if (cachedResult) return cachedResult;

        try {
            const ip = await this.resolveIp(url);
            if (!ip) return 'Unknown';

            const result = await this.retryApiCall(() => this.checkIpReputation(ip));
            await this.cacheApiResponse(url, 'abuseIpDb', result);
            return result;
        } catch (error) {
            console.error('Error checking AbuseIPDB:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async resolveIp(url: string): Promise<string | null> {
        try {
            const hostname = new URL(url).hostname;
            const response = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
            const data = await response.json();
            return data.Answer?.[0]?.data || null;
        } catch (error) {
            console.error('Error resolving IP:', error instanceof Error ? error.message : String(error));
            return null;
        }
    }

    private async checkIpReputation(ip: string): Promise<RiskState> {
        const params = new URLSearchParams({
            ipAddress: ip,
            maxAgeInDays: '90'
        });

        const response = await this.fetchWithTimeout(
            `${AbuseIPDBService.API_URL}?${params.toString()}`,
            {
                method: 'GET',
                headers: {
                    'Key': this.apiKey,
                    'Accept': 'application/json'
                }
            },
            5000
        );

        const data = await response.json();
        const score = data.data?.abuseConfidenceScore || 0;

        if (score > 75) return 'Phishing';
        if (score > 25) return 'Suspicious';
        return 'Safe';
    }
}