import { RiskState } from './types';

export class HeuristicAnalyzer {
  private static readonly SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure',
    'update', 'password', 'bank', 'paypal', 'amazon',
    'ebay', 'apple', 'microsoft', 'support', 'service',
    'alert', 'urgent', 'important', 'security', 'confirm'
  ];

  private static readonly SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.gq', '.ml', '.cf', 
    '.tk', '.rest', '.buzz', '.country', '.stream'
  ];

  private static readonly PHISHING_PATTERNS = [
    /http:\/\/[^/]+\/[^?]+\.php\?/, // PHP with query params
    /[^\w\d\-]\d{4,}[^\w\d\-]/,     // Suspicious numbers in domain
    /[^/]+\.[^/]+\.[^/]+/,          // Multiple subdomains
    /https?:\/\/(?!www\.).*\.(?:com|net|org)\//, // Non-www domains
    /[\u0400-\u04FF]/,              // Cyrillic characters
    /[\u4e00-\u9FFF]/,              // Chinese characters
    /[\u0600-\u06FF]/,              // Arabic characters
    /^https?:\/\/\d+\.\d+\.\d+\.\d+/ // IP address as domain
  ];

  public static analyze(url: string): RiskState {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      const fullUrl = url.toLowerCase();

      // 1. Check for suspicious keywords in hostname or path
      const hasSuspiciousKeyword = this.SUSPICIOUS_KEYWORDS.some(keyword => 
        hostname.includes(keyword) || pathname.includes(keyword)
      );

      // 2. Check for suspicious TLDs
      const hasSuspiciousTld = this.SUSPICIOUS_TLDS.some(tld => 
        hostname.endsWith(tld)
      );

      // 3. Check for known phishing patterns
      const hasPhishingPattern = this.PHISHING_PATTERNS.some(pattern => 
        pattern.test(fullUrl)
      );

      // 4. Check for homograph attacks (IDN)
      const hasIdn = /[^\x00-\x7F]/.test(hostname);

      // 5. Check for URL shortening services
      const isShortened = this.isShortenedUrl(hostname);

      // Scoring system
      let score = 0;
      if (hasSuspiciousKeyword) score += 30;
      if (hasSuspiciousTld) score += 20;
      if (hasPhishingPattern) score += 40;
      if (hasIdn) score += 30;
      if (isShortened) score += 20;

      // Determine risk state
      if (score >= 70) return 'Phishing';
      if (score >= 40) return 'Suspicious';
      return 'Safe';
    } catch (error) {
      console.error('Error in heuristic analysis:', error instanceof Error ? error.message : String(error));
      return 'Unknown';
    }
  }

  public static async checkHttpsAndSsl(url: string): Promise<RiskState> {
    try {
      if (!url.startsWith('https://')) {
        return 'Suspicious';
      }

      const hostname = new URL(url).hostname;
      
      // Basic SSL check - in a real extension you might use the webRequest API
      // to examine the actual certificate details
      const response = await fetch(`https://${hostname}`, { 
        method: 'HEAD',
        cache: 'no-store'
      });
      
      // Check for secure headers
      const strictTransportSecurity = response.headers.get('Strict-Transport-Security');
      const xFrameOptions = response.headers.get('X-Frame-Options');
      
      if (!strictTransportSecurity || !xFrameOptions) {
        return 'Suspicious';
      }
      
      return 'Safe';
    } catch (error) {
      console.error('Error checking HTTPS/SSL:', error instanceof Error ? error.message : String(error));
      return 'Suspicious';
    }
  }

  private static isShortenedUrl(hostname: string): boolean {
    const shorteners = [
      'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
      'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc'
    ];
    return shorteners.some(domain => hostname.includes(domain));
  }
}