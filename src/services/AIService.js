const crypto = require('crypto');
const axios = require('axios');
const CacheService = require('./CacheService');
const logger = require('../utils/logger');

class AIService {
  constructor() {
    this.cacheService = new CacheService();
    this.safeBrowsingApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    this.aiServiceUrl = process.env.AI_SERVICE_URL;
    this.aiServiceApiKey = process.env.AI_SERVICE_API_KEY;
  }

  /**
   * Generate hash for URL caching
   * @param {string} url - URL to hash
   * @returns {string} - SHA256 hash
   */
  static generateUrlHash(url) {
    return crypto.createHash('sha256').update(url).digest('hex');
  }

  /**
   * Analyze URL for spam, phishing, and malicious content
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} - Analysis results
   */
  static async analyzeUrl(url) {
    const urlHash = this.generateUrlHash(url);
    
    try {
      // Check cache first
      const cacheKey = `ai_analysis:${urlHash}`;
      const cachedResult = await CacheService.get(cacheKey);
      if (cachedResult) {
        logger.info('AI analysis cache hit', { url });
        return JSON.parse(cachedResult);
      }

      logger.info('Starting AI analysis for URL', { url });

      // Perform multiple analysis checks
      const [
        safeBrowsingResult,
        domainReputationResult,
        urlPatternResult,
        contentAnalysisResult
      ] = await Promise.allSettled([
        this.checkGoogleSafeBrowsing(url),
        this.checkDomainReputation(url),
        this.checkUrlPatterns(url),
        this.analyzeUrlContent(url)
      ]);

      // Combine results
      const analysisResult = this.combineAnalysisResults({
        url,
        safeBrowsing: safeBrowsingResult.status === 'fulfilled' ? safeBrowsingResult.value : null,
        domainReputation: domainReputationResult.status === 'fulfilled' ? domainReputationResult.value : null,
        urlPattern: urlPatternResult.status === 'fulfilled' ? urlPatternResult.value : null,
        contentAnalysis: contentAnalysisResult.status === 'fulfilled' ? contentAnalysisResult.value : null
      });

      // Cache results for 1 hour
      await CacheService.set(cacheKey, JSON.stringify(analysisResult), 3600);

      logger.info('AI analysis completed', { 
        url, 
        safetyScore: analysisResult.safetyScore,
        isBlocked: analysisResult.isBlocked
      });

      return analysisResult;
    } catch (error) {
      logger.error('AI analysis failed', { error: error.message, url });
      
      // Return safe defaults on error
      return {
        safetyScore: 0.5,
        isBlocked: false,
        reason: 'Analysis service unavailable',
        details: {
          safeBrowsing: { safe: true, reason: 'Service unavailable' },
          domainReputation: { trustScore: 0.5, reason: 'Service unavailable' },
          urlPattern: { safe: true, reason: 'Service unavailable' },
          contentAnalysis: { safe: true, reason: 'Service unavailable' }
        },
        analyzedAt: new Date().toISOString()
      };
    }
  }

  /**
   * Combine results from different analysis checks
   * @param {Object} results - Results from various checks
   * @returns {Object} - Combined analysis result
   */
  static combineAnalysisResults(results) {
    let riskScore = 0;
    let isBlocked = false;
    let blockingReason = null;
    const details = {};

    // Process Safe Browsing results
    if (results.safeBrowsing) {
      details.safeBrowsing = results.safeBrowsing;
      if (!results.safeBrowsing.safe) {
        riskScore += 0.8;
        isBlocked = true;
        blockingReason = 'Threat detected by Google Safe Browsing';
      }
    }

    // Process domain reputation
    if (results.domainReputation) {
      details.domainReputation = results.domainReputation;
      const domainRisk = results.domainReputation.riskScore || 0;
      riskScore += domainRisk * 0.3;
    }

    // Process URL pattern analysis
    if (results.urlPattern) {
      details.urlPattern = results.urlPattern;
      if (results.urlPattern.suspicious) {
        riskScore += 0.4;
        if (!blockingReason && results.urlPattern.reasons?.length > 0) {
          blockingReason = `Suspicious pattern: ${results.urlPattern.reasons[0]}`;
        }
      }
    }

    // Process content analysis
    if (results.contentAnalysis) {
      details.contentAnalysis = results.contentAnalysis;
      const contentRisk = results.contentAnalysis.riskScore || 0;
      riskScore += contentRisk * 0.5;
      if (contentRisk > 0.6 && !blockingReason) {
        blockingReason = 'Suspicious content detected';
      }
    }

    // Normalize risk score to safety score (inverted)
    const safetyScore = Math.max(0, 1 - Math.min(riskScore, 1));

    // Determine if URL should be blocked
    if (riskScore > 0.7) {
      isBlocked = true;
      if (!blockingReason) {
        blockingReason = 'High risk score detected';
      }
    }

    return {
      safetyScore,
      isBlocked,
      reason: blockingReason,
      details,
      analyzedAt: new Date().toISOString()
    };
  }

  /**
   * Check URL against Google Safe Browsing API
   * @param {string} url - URL to check
   * @returns {Promise<Object>} - Safe browsing results
   */
  static async checkGoogleSafeBrowsing(url) {
    const safeBrowsingApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!safeBrowsingApiKey) {
      return { safe: true, reason: 'API key not configured' };
    }

    try {
      const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingApiKey}`;
      
      const requestBody = {
        client: {
          clientId: 'url-shortener',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      };

      const response = await axios.post(apiUrl, requestBody, {
        timeout: 5000,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.data.matches && response.data.matches.length > 0) {
        const match = response.data.matches[0];
        return {
          safe: false,
          threat: true,
          threatType: match.threatType,
          platformType: match.platformType,
          reason: `Threat detected: ${match.threatType}`
        };
      }

      return {
        safe: true,
        threat: false,
        reason: 'No threats detected'
      };

    } catch (error) {
      logger.error('Safe Browsing API error:', error.response?.data || error.message);
      return {
        safe: true,
        error: error.message,
        reason: 'Safe Browsing check failed - defaulting to safe'
      };
    }
  }

  /**
   * Check domain reputation using various heuristics
   * @param {string} url - URL to check
   * @returns {Promise<Object>} - Domain reputation results
   */
  static async checkDomainReputation(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      let riskScore = 0;
      let category = 'unknown';

      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download'];
      if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
        riskScore += 0.3;
      }

      // Check for IP addresses instead of domains
      if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
        riskScore += 0.4;
      }

      // Check for suspicious patterns in domain
      if (/\d{4,}/.test(domain)) { // Many consecutive numbers
        riskScore += 0.2;
      }

      if (domain.length > 50) { // Very long domain
        riskScore += 0.1;
      }

      // Check for URL shortener domains (to prevent recursive shortening)
      const shortenerDomains = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.link'
      ];
      if (shortenerDomains.includes(domain)) {
        riskScore += 0.5;
        category = 'url_shortener';
      }

      // Categorize common domains
      if (domain.includes('github') || domain.includes('gitlab')) {
        category = 'development';
      } else if (domain.includes('google') || domain.includes('microsoft') || domain.includes('amazon')) {
        category = 'technology';
        riskScore = Math.max(0, riskScore - 0.2); // Lower risk for trusted domains
      } else if (domain.includes('news') || domain.includes('blog')) {
        category = 'media';
      }

      return {
        domain,
        riskScore: Math.min(riskScore, 1.0),
        category,
        checked: true
      };

    } catch (error) {
      logger.error('Domain reputation check error:', error);
      return {
        checked: false,
        error: error.message,
        riskScore: 0
      };
    }
  }

  /**
   * Check URL patterns for suspicious characteristics
   * @param {string} url - URL to check
   * @returns {Promise<Object>} - URL pattern analysis results
   */
  static async checkUrlPatterns(url) {
    try {
      let riskScore = 0;
      let suspicious = false;
      let reasons = [];

      // Check for suspicious patterns
      const suspiciousPatterns = [
        { pattern: /[^\x00-\x7F]/g, score: 0.3, reason: 'Non-ASCII characters' },
        { pattern: /localhost|127\.0\.0\.1/i, score: 0.6, reason: 'Localhost URL' },
        { pattern: /\.(exe|bat|com|scr|pif|msi)$/i, score: 0.8, reason: 'Executable file extension' },
        { pattern: /\b(phishing|scam|fake|malware|virus)\b/i, score: 0.7, reason: 'Suspicious keywords' },
        { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g, score: 0.4, reason: 'IP address instead of domain' },
        { pattern: /[a-zA-Z0-9]{30,}/g, score: 0.2, reason: 'Very long string parameters' }
      ];

      for (const { pattern, score, reason } of suspiciousPatterns) {
        if (pattern.test(url)) {
          riskScore += score;
          reasons.push(reason);
          suspicious = true;
        }
      }

      // Check URL length
      if (url.length > 200) {
        riskScore += 0.2;
        reasons.push('Very long URL');
        suspicious = true;
      }

      // Check for excessive subdomain nesting
      const urlObj = new URL(url);
      const subdomainLevels = urlObj.hostname.split('.').length - 2;
      if (subdomainLevels > 3) {
        riskScore += 0.1;
        reasons.push('Excessive subdomain nesting');
      }

      return {
        checked: true,
        suspicious,
        riskScore: Math.min(riskScore, 1.0),
        reasons,
        urlLength: url.length,
        subdomainLevels
      };

    } catch (error) {
      logger.error('URL pattern check error:', error);
      return {
        checked: false,
        error: error.message,
        riskScore: 0,
        suspicious: false
      };
    }
  }

  /**
   * Analyze URL content using AI service (if available)
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} - Content analysis results
   */
  static async analyzeUrlContent(url) {
    const aiServiceUrl = process.env.AI_SERVICE_URL;
    const aiServiceApiKey = process.env.AI_SERVICE_API_KEY;
    
    if (!aiServiceUrl || !aiServiceApiKey) {
      return {
        safe: true,
        reason: 'AI service not configured',
        riskScore: 0
      };
    }

    try {
      const response = await axios.post(`${aiServiceUrl}/analyze-url`, {
        url
      }, {
        headers: {
          'Authorization': `Bearer ${aiServiceApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      return {
        checked: true,
        riskScore: response.data.riskScore || 0,
        category: response.data.category,
        confidence: response.data.confidence,
        details: response.data.details
      };

    } catch (error) {
      logger.error('AI content analysis error:', error.response?.data || error.message);
      return {
        checked: false,
        error: error.message,
        riskScore: 0
      };
    }
  }

  /**
   * Calculate confidence score for the analysis
   * @param {Object} analysis - Analysis results
   * @returns {number} - Confidence score (0-1)
   */
  static calculateConfidence(analysis) {
    let confidence = 0;
    let checksCompleted = 0;

    Object.values(analysis.checks).forEach(check => {
      if (check && check.checked) {
        checksCompleted++;
        confidence += 0.25; // Each successful check adds 25% confidence
      }
    });

    // Bonus confidence for high-quality checks
    if (analysis.checks.safeBrowsing?.checked) {
      confidence += 0.2;
    }

    if (analysis.checks.contentAnalysis?.checked) {
      confidence += 0.15;
    }

    return Math.min(confidence, 1.0);
  }

  /**
   * Analyze click patterns for fraud detection
   * @param {Array} clickEvents - Recent click events
   * @returns {Object} - Fraud analysis results
   */
  static async analyzeClickFraud(clickEvents) {
    try {
      const analysis = {
        isFraudulent: false,
        riskScore: 0,
        reasons: [],
        patterns: {}
      };

      if (!clickEvents || clickEvents.length === 0) {
        return analysis;
      }

      // Group clicks by IP
      const ipGroups = {};
      clickEvents.forEach(click => {
        if (!ipGroups[click.hashedIp]) {
          ipGroups[click.hashedIp] = [];
        }
        ipGroups[click.hashedIp].push(click);
      });

      // Analyze patterns
      Object.entries(ipGroups).forEach(([ip, clicks]) => {
        // Check for rapid clicking
        if (clicks.length > 10) {
          analysis.riskScore += 0.3;
          analysis.reasons.push('High click volume from single IP');
        }

        // Check for bot-like behavior
        const userAgents = [...new Set(clicks.map(c => c.userAgent))];
        if (userAgents.length === 1 && clicks.length > 5) {
          analysis.riskScore += 0.2;
          analysis.reasons.push('Identical user agents');
        }

        // Check time patterns
        const timeIntervals = [];
        for (let i = 1; i < clicks.length; i++) {
          const interval = new Date(clicks[i].timestamp) - new Date(clicks[i-1].timestamp);
          timeIntervals.push(interval);
        }

        const avgInterval = timeIntervals.reduce((a, b) => a + b, 0) / timeIntervals.length;
        if (avgInterval < 1000 && clicks.length > 3) { // Less than 1 second between clicks
          analysis.riskScore += 0.4;
          analysis.reasons.push('Suspiciously fast clicking pattern');
        }
      });

      analysis.riskScore = Math.min(analysis.riskScore, 1.0);
      analysis.isFraudulent = analysis.riskScore > 0.5;

      return analysis;

    } catch (error) {
      logger.error('Click fraud analysis error:', error);
      return {
        isFraudulent: false,
        riskScore: 0,
        error: error.message
      };
    }
  }

  /**
   * Generate smart alias suggestions using AI
   * @param {string} url - Original URL
   * @param {string} title - Optional title
   * @returns {Promise<Array>} - Array of suggested aliases
   */
  static async generateSmartAliases(url, title = null) {
    try {
      const suggestions = [];
      
      // Extract meaningful words from URL
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/').filter(part => part.length > 2);
      const domain = urlObj.hostname.replace('www.', '');
      
      // Generate basic suggestions
      if (pathParts.length > 0) {
        suggestions.push(pathParts[pathParts.length - 1].slice(0, 10));
      }
      
      if (domain.split('.')[0].length < 15) {
        suggestions.push(domain.split('.')[0]);
      }

      // Use title if provided
      if (title) {
        const titleWords = title.toLowerCase()
          .replace(/[^a-z0-9\s]/g, '')
          .split(' ')
          .filter(word => word.length > 2)
          .slice(0, 3);
        
        if (titleWords.length > 0) {
          suggestions.push(titleWords.join('-'));
          suggestions.push(titleWords.map(w => w.charAt(0)).join(''));
        }
      }

      // Add random suggestions
      suggestions.push(this.generateRandomAlias());
      suggestions.push(this.generateRandomAlias());

      // Remove duplicates and invalid suggestions
      const validSuggestions = [...new Set(suggestions)]
        .filter(s => s && /^[a-zA-Z0-9_-]+$/.test(s) && s.length >= 3 && s.length <= 20)
        .slice(0, 5);

      return validSuggestions;

    } catch (error) {
      logger.error('Smart alias generation error:', error);
      return [this.generateRandomAlias(), this.generateRandomAlias()];
    }
  }

  /**
   * Generate a random alias
   * @returns {string} - Random alias
   */
  static generateRandomAlias() {
    const adjectives = ['quick', 'smart', 'cool', 'fast', 'nice', 'good', 'top', 'new'];
    const nouns = ['link', 'url', 'site', 'page', 'web', 'ref', 'go', 'jump'];
    
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    const num = Math.floor(Math.random() * 100);
    
    return `${adj}-${noun}-${num}`;
  }
}

module.exports = AIService; 