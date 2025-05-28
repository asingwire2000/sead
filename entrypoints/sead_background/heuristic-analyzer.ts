import { RiskState } from './types';

export class HeuristicAnalyzer {
  private static readonly TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com'
  ];

  private static readonly SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure',
    'update', 'password', 'bank', 'paypal'
  ];

  private static readonly SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.gq', '.ml', '.cf',
    '.tk', '.rest', '.buzz', '.country', '.stream'
  ];

  private static readonly PHISHING_PATTERNS = [
    /\/[^?]*\.php\?/,
    /^https?:\/\/\d+\.\d+\.\d+\.\d+/,
    /[\u0400-\u04FF]/, // Cyrillic
    /[\u4e00-\u9FFF]/, // Chinese
    /[\u0600-\u06FF]/  // Arabic
  ];

  private static readonly SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
    'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc'
  ];

  private static readonly THRESHOLDS = {
    phishing: 70,
    suspicious: 50
  };

  public static analyze(url: string): RiskState {
    try {
      const { hostname, pathname } = new URL(url.toLowerCase());

      if (this.isTrustedDomain(hostname)) return 'Safe';

      const scoreDetails = {
        keyword: this.containsKeyword(hostname, pathname) ? 10 : 0,
        tld: this.hasSuspiciousTld(hostname) ? 15 : 0,
        phishing: this.matchesPhishingPattern(url) ? 30 : 0,
        idn: this.isIdn(hostname) ? 25 : 0,
        shortener: this.isShortenedUrl(hostname) ? 20 : 0
      };

      const score = Object.values(scoreDetails).reduce((a, b) => a + b, 0);

      if (score >= this.THRESHOLDS.phishing) return 'Phishing';
      if (score >= this.THRESHOLDS.suspicious) return 'Suspicious';
      return 'Safe';

    } catch (err) {
      console.error('Heuristic error:', err);
      return 'Unknown';
    }
  }

  public static async checkHttpsAndSsl(url: string): Promise<RiskState> {
    try {
      const parsedUrl = new URL(url);

      // 1. Protocol check (basic)
      if (parsedUrl.protocol !== 'https:') {
        return 'Suspicious';
      }

      // 2. In extension context, use webRequest API for deeper checks
      if (typeof browser !== 'undefined' && browser.webRequest) {
        return new Promise((resolve) => {
          // This is simplified - real implementation would track requests
          resolve('Safe'); // Assume safe in extension context
        });
      }

      // 3. Fallback for non-extension contexts (testing)
      const securityHeaders = await this.fetchSecurityHeaders(url);

      return this.evaluateSecurityHeaders(securityHeaders);

    } catch (error) {
      console.error('HTTPS/SSL check error:', error);
      return 'Suspicious';
    }
  }

  private static async fetchSecurityHeaders(url: string): Promise<Record<string, string>> {
    try {
      const parsedUrl = new URL(url);
      const originUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}`;


      console.log('getting headers')
      const response = await fetch(originUrl, {
        method: 'HEAD',
        redirect: 'manual', // Don't follow redirects
        cache: 'no-store'
      });

      console.log('res :' + response.headers.entries + response.status);
      const headers: Record<string, string> = {};
      [
        'strict-transport-security',
        'x-frame-options',
        'x-content-type-options',
        'content-security-policy'
      ].forEach(header => {
        const value = response.headers.get(header);
        if (value) headers[header] = value;
      });
      console.log('header :' + headers);
      return headers;
    } catch (error) {
      console.error('Failed to fetch headers:', error);
      return {};
    }
  }

  private static evaluateSecurityHeaders(headers: Record<string, string>): RiskState {
    const hasHSTS = !!headers['strict-transport-security'];
    const hasXFO = !!headers['x-frame-options'];
    const hasXCTO = !!headers['x-content-type-options'];
    const hasCSP = !!headers['content-security-policy'];

    const score = [hasHSTS, hasXFO, hasXCTO, hasCSP].filter(Boolean).length;

    if (score >= 3) return 'Safe';
    if (score >= 1) return 'Suspicious';
    return 'Suspicious';
  }

  private static isTrustedDomain(hostname: string): boolean {
    return this.TRUSTED_DOMAINS.some(domain => hostname.endsWith(domain));
  }

  private static containsKeyword(hostname: string, path: string): boolean {
    return this.SUSPICIOUS_KEYWORDS.some(k =>
      new RegExp(`\\b${k}\\b`, 'i').test(hostname + path)
    );
  }

  private static hasSuspiciousTld(hostname: string): boolean {
    return this.SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
  }

  private static matchesPhishingPattern(url: string): boolean {
    return this.PHISHING_PATTERNS.some(pattern => pattern.test(url));
  }

  private static isIdn(hostname: string): boolean {
    return /[^\x00-\x7F]/.test(hostname) || hostname.startsWith('xn--');
  }

  private static isShortenedUrl(hostname: string): boolean {
    return this.SHORTENERS.some(short => hostname.includes(short));
  }
}
