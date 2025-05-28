import ApiService from "./api-service";
import { StorageService } from "./storage-service";
import { RiskState } from "./types";

interface IpReputationRecord {
    ip: string;
    risk: RiskState;
    source: string;
    lastChecked: number;
}

export class IpReputationService extends ApiService {
    private static readonly CACHE_KEY = 'ipReputationCache';
    private static readonly CACHE_TTL = 24 * 60 * 60 * 1000;


    // You can rotate between multiple APIs or services
    private static readonly SERVICES = [
        'https://api.abuseipdb.com/api/v2/check',
        'https://ipqualityscore.com/api/json/ip',
        'https://api.ipapi.is/reputation' // hypothetical fallback
    ];

    constructor(private ipAbuseApiKey: string) {
        super();
        if (!ipAbuseApiKey) {
            throw Error('IpAbuse API key not provided.');
        }
    }

    public async checkUrl(url: string): Promise<RiskState> {

        const ip = await this.extractIpFromUrl(url);
        console.log(ip);
        if (!ip) throw new Error('No IP found for IP reputation check');


        const cached = await this.getCachedReputation(ip);
        if (cached) return cached.risk;

        try {
            const record = await this.queryReputationApis(ip);
            if (record) {
                await this.storeInCache(ip, record);
                return record.risk;
            }
        } catch (error) {
            console.error('[IP Reputation] Error checking IP:', error instanceof Error ? error.message : String(error));
        }

        return 'Unknown';
    }

    private async queryReputationApis(ip: string): Promise<IpReputationRecord | null> {
        for (const service of IpReputationService.SERVICES) {
            try {
                const url = new URL(service);
                url.searchParams.set('ip', ip);

                const headers: Record<string, string> = {};
                if (service.includes('abuseipdb')) headers['Key'] = this.ipAbuseApiKey;
                if (service.includes('ipqualityscore')) headers['Authorization'] = 'Bearer YOUR_IPQS_KEY';

                const response = await this.fetchWithTimeout(url.toString(), { headers }, 5000);
                const data = await response.json();

                const risk = this.interpretRisk(data);
                if (risk) {
                    return {
                        ip,
                        risk,
                        source: service,
                        lastChecked: Date.now(),
                    };
                }
            } catch (error) {
                console.warn(`[IP Reputation] Failed with service: ${service}`, error instanceof Error ? error.message : String(error));
                continue; // gracefully move to next
            }
        }

        return null;
    }

    private async extractIpFromUrl(url: string): Promise<string | null> {
        try {
            const parsed = new URL(url);
            const hostname = parsed.hostname;

            // If it's already an IP address, return it
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
                return hostname;
            }

            // Resolve domain to IP using Google's DNS-over-HTTPS API
            const response = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
            if (!response.ok) {
                console.warn(`DNS resolution failed: ${response.statusText}`);
                return null;
            }

            const data = await response.json();

            // Extract the first A record (IPv4)
            const answer = data.Answer?.find((record: any) => record.type === 1);
            return answer?.data || null;
        } catch (error) {
            console.warn('Failed to extract IP from URL:', error);
            return null;
        }
    }


    private interpretRisk(data: any): RiskState {
        if (data.abuseConfidenceScore >= 85 || data.fraud_score >= 85) return 'Phishing';
        if (data.abuseConfidenceScore >= 50 || data.fraud_score >= 50) return 'Suspicious';
        return 'Safe';
    }

    private async getCachedReputation(ip: string): Promise<IpReputationRecord | null> {
        const cache = await StorageService.getItem<Record<string, IpReputationRecord>>(IpReputationService.CACHE_KEY) || {};
        const record = cache[ip];
        if (!record) return null;

        const isFresh = Date.now() - record.lastChecked < IpReputationService.CACHE_TTL;
        return isFresh ? record : null;
    }

    private async storeInCache(ip: string, record: IpReputationRecord): Promise<void> {
        const cache = await StorageService.getItem<Record<string, IpReputationRecord>>(IpReputationService.CACHE_KEY) || {};
        cache[ip] = record;
        await StorageService.setItem(IpReputationService.CACHE_KEY, cache);
    }
}
