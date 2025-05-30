import ApiService from "./api-service";
import { RiskState } from "./types";


export default class GoogleSafeBrowsingService extends ApiService {
    private static readonly API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=';

    constructor(private apiKey: string) {
        super();

        if (!apiKey || apiKey === 'AIzaSyC0jhIYEXeMljK8SBfuuAzw176dE3M8LQ8') {
            console.error('Google Safe Browsing API key is missing or invalid.');
        }
    }

    public async checkUrl(url: string): Promise<RiskState> {
        if (!this.apiKey) {
            return 'Unknown';
        }

        const cachedResult = await this.getCachedApiResponse(url, 'googleSafeBrowsing');
        if (cachedResult) return cachedResult;

        try {
            const result = await this.retryApiCall(() => this.checkUrlWithApi(url));
            await this.cacheApiResponse(url, 'googleSafeBrowsing', result);
            return result;
        } catch (error) {
            console.error('Error querying Google Safe Browsing:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async checkUrlWithApi(url: string): Promise<RiskState> {
        const requestBody = {
            client: { clientId: 'sead-extension', clientVersion: '1.0.0' },
            threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
            }
        };

        const response = await this.fetchWithTimeout(
            `${GoogleSafeBrowsingService.API_URL}${this.apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            },
            5000
        );

        const data = await response.json();
        return this.parseApiResponse(data);
    }

    private parseApiResponse(data: any): RiskState {
        if (!data.matches) return 'Safe';

        const threatTypes = data.matches.map((match: any) => match.threatType);
        if (threatTypes.includes('SOCIAL_ENGINEERING')) {
            return 'Phishing';
        }
        if (threatTypes.some((t: string) =>
            ['MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'].includes(t)
        )) {
            return 'Suspicious';
        }
        return 'Safe';
    }
}

