import ApiService from "./api-service";
import { StorageService } from "./storage-service";
import { PhishTankDatabase, RiskState } from "./types";

export class PhishTankService extends ApiService {
    private static readonly PHISHTANK_DB_KEY = 'phishTankDatabase';
    private static readonly PHISHTANK_DB_TIMESTAMP_KEY = 'phishTankDbTimestamp';
    private static readonly DATABASE_URL = 'https://data.phishtank.com/data/online-valid.json';
    private static readonly UPDATE_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

    public async checkUrl(url: string): Promise<RiskState> {
        const cachedResult = await this.getCachedApiResponse(url, 'phishTank');
        if (cachedResult) return cachedResult;

        try {
            if (await this.shouldUpdateDatabase()) {
                await this.fetchDatabase();
            }

            const database = await this.getDatabase();
            const entry = database[url];
            const result = entry ? (entry.valid ? 'Phishing' : 'Suspicious') : 'Safe';

            await this.cacheApiResponse(url, 'phishTank', result);
            return result;
        } catch (error) {
            console.error('Error checking PhishTank database:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async shouldUpdateDatabase(): Promise<boolean> {
        const lastUpdate = await StorageService.getItem<number>(PhishTankService.PHISHTANK_DB_TIMESTAMP_KEY) || 0;
        return Date.now() - lastUpdate > PhishTankService.UPDATE_INTERVAL;
    }

    private async fetchDatabase(): Promise<void> {
        try {
            console.log('Fetching PhishTank database...');
            const response = await this.fetchWithTimeout(PhishTankService.DATABASE_URL, {}, 5000);
            const data = await response.json();

            const database: PhishTankDatabase = {};
            data.forEach((item: any) => {
                database[item.url] = item;
            });

            await Promise.all([
                StorageService.setItem(PhishTankService.PHISHTANK_DB_KEY, database),
                StorageService.setItem(PhishTankService.PHISHTANK_DB_TIMESTAMP_KEY, Date.now())
            ]);

            console.log('PhishTank database updated successfully');
        } catch (error) {
            console.error('Error fetching PhishTank database:', error instanceof Error ? error.message : String(error));
            throw error;
        }
    }

    private async getDatabase(): Promise<PhishTankDatabase> {
        return await StorageService.getItem<PhishTankDatabase>(PhishTankService.PHISHTANK_DB_KEY) || {};
    }
}
