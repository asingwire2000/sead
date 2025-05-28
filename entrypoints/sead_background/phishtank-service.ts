import ApiService from "./api-service";
import { StorageService } from "./storage-service";
import { PhishTankDatabase, RiskState } from "./types";

export class PhishTankService extends ApiService {
    private static readonly DB_KEY = 'phishTankDatabase';
    private static readonly TIMESTAMP_KEY = 'phishTankDbTimestamp';
    private static readonly DATABASE_URL = 'https://data.phishtank.com/data/online-valid.json';
    private static readonly MAX_CACHE_AGE = 24 * 60 * 60 * 1000; // 24 hours
    private static readonly MAX_DB_SIZE = 5 * 1024 * 1024; // 5MB (just for sanity)

    public async checkUrl(url: string): Promise<RiskState> {
        const cached = await this.getCachedApiResponse(url, 'phishTank');
        if (cached) return cached;

        try {
            if (await this.shouldRefreshDatabase()) {
                await this.refreshDatabaseSafely();
            }

            const db = await this.getDatabase();
            const entry = db[url];
            const result: RiskState = entry?.valid ? 'Phishing' : (entry ? 'Suspicious' : 'Safe');

            await this.cacheApiResponse(url, 'phishTank', result);
            return result;

        } catch (error) {
            console.error('[PhishTank] Error:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async shouldRefreshDatabase(): Promise<boolean> {
        const lastUpdated = await StorageService.getItem<number>(PhishTankService.TIMESTAMP_KEY) || 0;
        return Date.now() - lastUpdated > PhishTankService.MAX_CACHE_AGE;
    }

    private async refreshDatabaseSafely(): Promise<void> {
        try {
            console.log('[PhishTank] Refreshing database...');
            const response = await this.fetchWithTimeout(PhishTankService.DATABASE_URL, {}, 5000);

            if (!response.ok) throw new Error(`Failed to fetch: ${response.status}`);

            const data = await response.json();
            const db: PhishTankDatabase = {};

            for (const item of data) {
                if (typeof item?.url === 'string') db[item.url] = item;
            }

            const dbSize = JSON.stringify(db).length;
            if (dbSize > PhishTankService.MAX_DB_SIZE) {
                console.warn('[PhishTank] Database too large; skipping save to avoid quota issues.');
                return;
            }

            await Promise.all([
                StorageService.setItem(PhishTankService.DB_KEY, db),
                StorageService.setItem(PhishTankService.TIMESTAMP_KEY, Date.now())
            ]);

            console.log('[PhishTank] Database updated successfully');

        } catch (error) {
            console.error('[PhishTank] Failed to refresh database:', error instanceof Error ? error.message : String(error));
        }
    }

    private async getDatabase(): Promise<PhishTankDatabase> {
        return await StorageService.getItem<PhishTankDatabase>(PhishTankService.DB_KEY) || {};
    }
}
