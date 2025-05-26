import { StorageService } from './storage-service';
import { RiskState, ApiSource, PhishTankDatabase, ApiConfig } from './types';


export default abstract class ApiService {
  protected static readonly API_CACHE_EXPIRATION = 24 * 60 * 60 * 1000; // 24 hours
  protected static readonly MAX_CACHE_ENTRIES = 500;

  protected async fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 5000): Promise<Response> {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      console.log(`Fetching URL: ${url}`);
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(id);
      return response;
    } catch (error) {
      clearTimeout(id);
      console.error(`Fetch error for ${url}:`, error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  protected async retryApiCall<T>(fn: () => Promise<T>, maxRetries = 1): Promise<T> {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === maxRetries - 1) {
          console.error(`Failed after ${maxRetries} retries:`, error instanceof Error ? error.message : String(error));
          throw error;
        }
        console.log(`Retrying after 1 second... (Attempt ${i + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    throw new Error('Unexpected error in retryApiCall');
  }

  protected async getCachedApiResponse(url: string, source: string): Promise<RiskState | null> {
    const cacheKey = this.getCacheKey(url, source);
    const apiCache = await StorageService.getApiCache();
    
    if (apiCache[cacheKey]) {
      const cacheEntry = apiCache[cacheKey];
      const cacheAge = Date.now() - cacheEntry.timestamp;
      
      if (cacheAge < ApiService.API_CACHE_EXPIRATION) {
        console.log(`Using cached response for ${source} on ${url}`);
        return cacheEntry.result;
      } else {
        // Remove expired cache entry
        const newCache = { ...apiCache };
        delete newCache[cacheKey];
        await StorageService.setApiCache(newCache);
      }
    }
    return null;
  }

  protected async cacheApiResponse(url: string, source: string, result: RiskState): Promise<void> {
    const cacheKey = this.getCacheKey(url, source);
    const apiCache = await StorageService.getApiCache();
    
    const updatedCache = {
      ...apiCache,
      [cacheKey]: { result, timestamp: Date.now() }
    };

    // Enforce cache size limit
    const cacheEntries = Object.entries(updatedCache);
    const finalCache = cacheEntries.length > ApiService.MAX_CACHE_ENTRIES
      ? Object.fromEntries(cacheEntries.slice(0, ApiService.MAX_CACHE_ENTRIES))
      : updatedCache;

    await StorageService.setApiCache(finalCache);
    console.log(`Cached response for ${source} on ${url}`);
  }

  private getCacheKey(url: string, source: string): string {
    return `${url}:${source}`;
  }
}
