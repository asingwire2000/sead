import { storage } from '#imports';
import { RiskState, CacheEntry, LinkHistoryEntry } from './types';


export class StorageService {
    private static readonly URL_CACHE_KEY = 'local:urlCache';
    private static readonly LINK_HISTORY_KEY = 'local:linkHistory';
    private static readonly MAX_CACHE_ENTRIES = 100;
    private static readonly MAX_HISTORY_ENTRIES = 50;

    /**
     * Clears the cache entry for a specific URL
     * @param url The URL to clear from cache
     */
    static async clearCacheForUrl(url: string): Promise<void> {
        try {
            const cache = await storage.getItem<Record<string, CacheEntry>>(this.URL_CACHE_KEY) || {};

            if (cache[url]) {
                const newCache = { ...cache };
                delete newCache[url];
                await storage.setItem(this.URL_CACHE_KEY, newCache);
                console.log(`Cache cleared for URL: ${url}`);
            }
        } catch (error) {
            console.error(`Error clearing cache for URL ${url}:`, error);
            throw new Error(`Failed to clear cache for URL: ${url}`);
        }
    }

    /**
     * Removes all history entries for a specific URL
     * @param url The URL to remove from history
     */
    static async clearHistoryForUrl(url: string): Promise<void> {
        try {
            const history = await storage.getItem<LinkHistoryEntry[]>(this.LINK_HISTORY_KEY) || [];

            const filteredHistory = history.filter(entry => entry.url !== url);

            if (filteredHistory.length < history.length) {
                await storage.setItem(this.LINK_HISTORY_KEY, filteredHistory);
                console.log(`History cleared for URL: ${url}`);
            }
        } catch (error) {
            console.error(`Error clearing history for URL ${url}:`, error);
            throw new Error(`Failed to clear history for URL: ${url}`);
        }
    }

    /**
     * Saves analysis results to cache
     * @param url The URL being analyzed
     * @param entry The cache entry data (without timestamp)
     */
    static async saveToCache(url: string, entry: Omit<CacheEntry, 'timestamp'>): Promise<void> {
        try {
            const cache = await storage.getItem<Record<string, CacheEntry>>(this.URL_CACHE_KEY) || {};

            const updatedCache = {
                ...cache,
                [url]: {
                    ...entry,
                    timestamp: Date.now()
                }
            };

            // Enforce cache size limit
            const cacheEntries = Object.entries(updatedCache);
            const trimmedCache = cacheEntries.length > this.MAX_CACHE_ENTRIES
                ? Object.fromEntries(cacheEntries.slice(0, this.MAX_CACHE_ENTRIES))
                : updatedCache;

            await storage.setItem(this.URL_CACHE_KEY, trimmedCache);
            console.log('Cache updated successfully');
        } catch (error) {
            console.error('Error saving to cache:', error);
            throw new Error('Failed to save to cache');
        }
    }

    /**
     * Saves analysis results to history
     * @param entry The history entry to save
     */
    static async saveToHistory(entry: LinkHistoryEntry): Promise<void> {
        try {
            const history = await storage.getItem<LinkHistoryEntry[]>(this.LINK_HISTORY_KEY) || [];

            let updatedHistory: LinkHistoryEntry[];

            if (entry.isInterim) {
                // Add interim entry
                updatedHistory = [entry, ...history];
            } else {
                // Replace any interim entry and add final result
                updatedHistory = [
                    entry,
                    ...history.filter(item => !(item.url === entry.url && item.isInterim))
                ];
            }

            // Enforce history size limit
            if (updatedHistory.length > this.MAX_HISTORY_ENTRIES) {
                updatedHistory = updatedHistory.slice(0, this.MAX_HISTORY_ENTRIES);
            }

            await storage.setItem(this.LINK_HISTORY_KEY, updatedHistory);
            console.log('History updated successfully');
        } catch (error) {
            console.error('Error saving to history:', error);
            throw new Error('Failed to save to history');
        }
    }

    /**
     * Retrieves the current URL cache
     */
    static async getUrlCache(): Promise<Record<string, CacheEntry>> {
        try {
            return await storage.getItem<Record<string, CacheEntry>>(this.URL_CACHE_KEY) || {};
        } catch (error) {
            console.error('Error retrieving URL cache:', error);
            throw new Error('Failed to retrieve URL cache');
        }
    }

    /**
     * Retrieves the link history
     */
    static async getLinkHistory(): Promise<LinkHistoryEntry[]> {
        try {
            return await storage.getItem<LinkHistoryEntry[]>(this.LINK_HISTORY_KEY) || [];
        } catch (error) {
            console.error('Error retrieving link history:', error);
            throw new Error('Failed to retrieve link history');
        }
    }

    /**
     * Retrieves a specific cache entry for a URL
     */
    static async getCacheEntry(url: string): Promise<CacheEntry | null> {
        try {
            const cache = await this.getUrlCache();
            return cache[url] || null;
        } catch (error) {
            console.error(`Error retrieving cache entry for ${url}:`, error);
            throw new Error(`Failed to retrieve cache entry for ${url}`);
        }
    }

    static async getApiCache(): Promise<Record<string, { result: RiskState; timestamp: number }>> {
        return await this.getItem('apiCache') || {};
    }

    static async setApiCache(cache: Record<string, { result: RiskState; timestamp: number }>): Promise<void> {
        await this.setItem('apiCache', cache);
    }


    static async getItem<T>(key: string): Promise<T | null> {
        return await storage.getItem<T>(`local:${key}`);
    }

    static async setItem(key: string, value: any): Promise<void> {
        await storage.setItem(`local:${key}`, value);
    }
}