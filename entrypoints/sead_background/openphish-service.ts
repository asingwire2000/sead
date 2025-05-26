import ApiService from './api-service';
import { StorageService } from './storage-service';
import { RiskState } from './types';

export class OpenPhishService extends ApiService {
    private static readonly API_URL = 'https://openphish.com/feed.txt';
    private static readonly CACHE_KEY = 'openPhishData';
    private static readonly CACHE_TIMESTAMP_KEY = 'openPhishDataTimestamp';
    private static readonly UPDATE_INTERVAL = 60 * 60 * 1000; // 1 hour

    public async checkUrl(url: string): Promise<RiskState> {
        const cachedResult = await this.getCachedApiResponse(url, 'openPhish');
        if (cachedResult) return cachedResult;

        try {
            if (await this.shouldUpdateFeed()) {
                await this.updateFeed();
            }

            const phishingUrls = await this.getPhishingUrls();
            const result = phishingUrls.includes(url) ? 'Phishing' : 'Safe';

            await this.cacheApiResponse(url, 'openPhish', result);
            return result;
        } catch (error) {
            console.error('Error checking OpenPhish:', error instanceof Error ? error.message : String(error));
            return 'Unknown';
        }
    }

    private async shouldUpdateFeed(): Promise<boolean> {
        try {
            const lastUpdate = await StorageService.getItem<number>(OpenPhishService.CACHE_TIMESTAMP_KEY) || 0;
            return Date.now() - lastUpdate > OpenPhishService.UPDATE_INTERVAL;
        } catch (error) {
            console.error('Error checking feed update status:', error instanceof Error ? error.message : String(error));
            return true; // Default to updating if we can't check
        }
    }

    private async updateFeed(): Promise<void> {
        try {
            console.log('Updating OpenPhish feed...');
            const response = await this.fetchWithTimeout(OpenPhishService.API_URL, {}, 5000);
            const text = await response.text();
            const phishingUrls = text.split('\n').filter(line => line.trim() !== '');

            await Promise.all([
                StorageService.setItem(OpenPhishService.CACHE_KEY, phishingUrls),
                StorageService.setItem(OpenPhishService.CACHE_TIMESTAMP_KEY, Date.now())
            ]);

            console.log('OpenPhish feed updated successfully');
        } catch (error) {
            console.error('Error updating OpenPhish feed:', error instanceof Error ? error.message : String(error));
            throw error;
        }
    }

    private async getPhishingUrls(): Promise<string[]> {
        try {
            return await StorageService.getItem<string[]>(OpenPhishService.CACHE_KEY) || [];
        } catch (error) {
            console.error('Error retrieving phishing URLs:', error instanceof Error ? error.message : String(error));
            return [];
        }
    }
}