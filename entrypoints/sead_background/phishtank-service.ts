import ApiService from './api-service';
import { StorageService } from './storage-service';
import { PhishTankDatabase, RiskState } from './types';

export class PhishTankService extends ApiService {
    private static readonly DB_KEY = 'phishTankDatabase';
    private static readonly TIMESTAMP_KEY = 'phishTankDbTimestamp';
    private static readonly DATABASE_URL = 'https://data.phishtank.com/data/online-valid.json';
    private static readonly API_URL = 'https://checkurl.phishtank.com/checkurl/';
    private static readonly MAX_CACHE_AGE = 24 * 60 * 60 * 1000; // 24 hours
    private static readonly MAX_DB_SIZE = 5 * 1024 * 1024; // 5MB

    public async checkUrl(url: string): Promise<RiskState> {
        const cached = await this.getCachedApiResponse(url, 'phishTank');
        if (cached) return cached;

        try {
            // Try cached DB method first
            if (await this.shouldRefreshDatabase()) {
                await this.refreshDatabaseSafely();
            }

            const dbResult = await this.lookupFromDatabase(url);
            if (dbResult !== 'Unknown') {
                await this.cacheApiResponse(url, 'phishTank', dbResult);
                return dbResult;
            }

            // Fallback to live API query
            const apiResult = await this.queryPhishTankApi(url);
            await this.cacheApiResponse(url, 'phishTank', apiResult);
            return apiResult;

        } catch (error) {
            console.error('[PhishTank] checkUrl error:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    // --- Local Cache Methods ---

    private async shouldRefreshDatabase(): Promise<boolean> {
        const lastUpdated = await StorageService.getItem<number>(PhishTankService.TIMESTAMP_KEY) || 0;
        return Date.now() - lastUpdated > PhishTankService.MAX_CACHE_AGE;
    }

    private async refreshDatabaseSafely(): Promise<void> {
        try {
            console.log('[PhishTank] Refreshing local database...');
            const response = await this.fetchWithTimeout(PhishTankService.DATABASE_URL, {}, 5000);
            if (!response.ok) throw new Error(`Download failed: ${response.status}`);

            const data = await response.json();
            const db: PhishTankDatabase = {};

            for (const item of data) {
                if (typeof item?.url === 'string') {
                    db[item.url] = item;
                }
            }

            const dbSize = JSON.stringify(db).length;
            if (dbSize > PhishTankService.MAX_DB_SIZE) {
                console.warn('[PhishTank] Skipping save; DB size too large.');
                return;
            }

            await Promise.all([
                StorageService.setItem(PhishTankService.DB_KEY, db),
                StorageService.setItem(PhishTankService.TIMESTAMP_KEY, Date.now())
            ]);

            console.log('[PhishTank] Database refreshed successfully.');
        } catch (error) {
            console.error('[PhishTank] Failed to refresh database:', error instanceof Error ? error.message : String(error));
        }
    }

    private async getDatabase(): Promise<PhishTankDatabase> {
        return await StorageService.getItem<PhishTankDatabase>(PhishTankService.DB_KEY) || {};
    }

    private async lookupFromDatabase(url: string): Promise<RiskState> {
        const db = await this.getDatabase();
        const entry = db[url];

        if (entry?.valid) return 'Phishing';
        if (entry) return 'Suspicious';
        return 'Unknown';
    }

    // --- Live API Fallback ---

    private async queryPhishTankApi(url: string): Promise<RiskState> {
        try {
            const form = new URLSearchParams();
            form.set('url', url);
            form.set('format', 'json');
            // form.set('app_key', 'YOUR_API_KEY'); // Optional if you have one

            const response = await fetch(PhishTankService.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'phish-detector/1.0'
                },
                body: form.toString()
            });

            if (!response.ok) throw new Error(`API returned status ${response.status}`);

            const json = await response.json();
            const result = json.results;

            if (result.valid && result.verified) return 'Phishing';
            if (result.in_database) return 'Suspicious';
            return 'Unknown';

        } catch (error) {
            console.error('[PhishTank] API query failed:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }
}
