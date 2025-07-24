const databaseConfig = require('../config/database');
const logger = require('../utils/logger');

class CacheService {
  static getClient() {
    return databaseConfig.getRedisClient();
  }

  static getDefaultTTL() {
    return parseInt(process.env.DEFAULT_CACHE_TTL) || 3600; // 1 hour
  }

  /**
   * Set URL mapping in cache
   * @param {string} shortId - Short ID
   * @param {string} longUrl - Long URL
   * @param {number} ttl - Time to live in seconds
   */
  static async setUrlMapping(shortId, longUrl, ttl = null) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `url:${shortId}`;
      const data = {
        longUrl,
        cachedAt: Date.now()
      };

      const ttlValue = ttl || this.getDefaultTTL();
      await client.setEx(cacheKey, ttlValue, JSON.stringify(data));
      logger.debug(`Cached URL mapping: ${shortId}`);
    } catch (error) {
      logger.error('Error setting URL mapping in cache:', error);
    }
  }

  /**
   * Get URL mapping from cache
   * @param {string} shortId - Short ID
   * @returns {Promise<string|null>} - Long URL or null
   */
  static async getUrlMapping(shortId) {
    const client = this.getClient();
    if (!client) return null;

    try {
      const cacheKey = `url:${shortId}`;
      const cachedData = await client.get(cacheKey);

      if (!cachedData) {
        return null;
      }

      const data = JSON.parse(cachedData);
      logger.debug(`Cache hit for URL mapping: ${shortId}`);
      return data.longUrl;
    } catch (error) {
      logger.error('Error getting URL mapping from cache:', error);
      return null;
    }
  }

  /**
   * Delete URL mapping from cache
   * @param {string} shortId - Short ID
   */
  static async deleteUrlMapping(shortId) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `url:${shortId}`;
      await client.del(cacheKey);
      logger.debug(`Deleted URL mapping from cache: ${shortId}`);
    } catch (error) {
      logger.error('Error deleting URL mapping from cache:', error);
    }
  }

  /**
   * Generic get method
   * @param {string} key - Cache key
   * @returns {Promise<string|null>} - Cached value or null
   */
  static async get(key) {
    const client = this.getClient();
    if (!client) return null;

    try {
      return await client.get(key);
    } catch (error) {
      logger.error('Error getting from cache:', error);
      return null;
    }
  }

  /**
   * Generic set method
   * @param {string} key - Cache key
   * @param {string} value - Value to cache
   * @param {number} ttl - Time to live in seconds
   */
  static async set(key, value, ttl = null) {
    const client = this.getClient();
    if (!client) return;

    try {
      const ttlValue = ttl || this.getDefaultTTL();
      await client.setEx(key, ttlValue, value);
      logger.debug(`Cached: ${key}`);
    } catch (error) {
      logger.error('Error setting cache:', error);
    }
  }

  /**
   * Update click count in cache
   * @param {string} shortId - Short ID
   * @param {number} newCount - New click count
   */
  static async updateClickCount(shortId, newCount) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `url:${shortId}`;
      const cachedData = await client.get(cacheKey);

      if (cachedData) {
        const data = JSON.parse(cachedData);
        data.clickCount = newCount;
        data.lastUpdated = Date.now();

        await client.setEx(cacheKey, this.getDefaultTTL(), JSON.stringify(data));
        logger.debug(`Updated click count in cache: ${shortId} -> ${newCount}`);
      }
    } catch (error) {
      logger.error('Error updating click count in cache:', error);
    }
  }

  /**
   * Invalidate URL mapping cache
   * @param {string} shortId - Short ID
   */
  static async invalidateUrlMapping(shortId) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `url:${shortId}`;
      await client.del(cacheKey);
      logger.debug(`Invalidated cache for URL: ${shortId}`);
    } catch (error) {
      logger.error('Error invalidating URL mapping cache:', error);
    }
  }

  /**
   * Cache analytics data
   * @param {string} key - Cache key
   * @param {Object} data - Analytics data
   * @param {number} ttl - Time to live in seconds
   */
  static async setAnalytics(key, data, ttl = 300) { // 5 minutes for analytics
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `analytics:${key}`;
      await client.setEx(cacheKey, ttl, JSON.stringify(data));
      logger.debug(`Cached analytics data: ${key}`);
    } catch (error) {
      logger.error('Error caching analytics data:', error);
    }
  }

  /**
   * Get analytics data from cache
   * @param {string} key - Cache key
   * @returns {Promise<Object|null>} - Cached analytics or null
   */
  static async getAnalytics(key) {
    const client = this.getClient();
    if (!client) return null;

    try {
      const cacheKey = `analytics:${key}`;
      const cachedData = await client.get(cacheKey);

      if (!cachedData) {
        return null;
      }

      logger.debug(`Analytics cache hit: ${key}`);
      return JSON.parse(cachedData);
    } catch (error) {
      logger.error('Error getting analytics from cache:', error);
      return null;
    }
  }

  /**
   * Cache rate limiting data
   * @param {string} identifier - IP, user ID, or API key
   * @param {string} window - Time window identifier
   * @param {number} count - Current request count
   * @param {number} ttl - Time to live in seconds
   */
  static async setRateLimit(identifier, window, count, ttl) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `rate_limit:${identifier}:${window}`;
      await client.setEx(cacheKey, ttl, count.toString());
    } catch (error) {
      logger.error('Error setting rate limit in cache:', error);
    }
  }

  /**
   * Get rate limiting data
   * @param {string} identifier - IP, user ID, or API key
   * @param {string} window - Time window identifier
   * @returns {Promise<number>} - Current request count
   */
  static async getRateLimit(identifier, window) {
    const client = this.getClient();
    if (!client) return 0;

    try {
      const cacheKey = `rate_limit:${identifier}:${window}`;
      const count = await client.get(cacheKey);
      return count ? parseInt(count) : 0;
    } catch (error) {
      logger.error('Error getting rate limit from cache:', error);
      return 0;
    }
  }

  /**
   * Increment rate limit counter
   * @param {string} identifier - IP, user ID, or API key
   * @param {string} window - Time window identifier
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<number>} - New count
   */
  static async incrementRateLimit(identifier, window, ttl) {
    const client = this.getClient();
    if (!client) return 1;

    try {
      const cacheKey = `rate_limit:${identifier}:${window}`;
      const multi = client.multi();
      multi.incr(cacheKey);
      multi.expire(cacheKey, ttl);
      const results = await multi.exec();
      return results[0];
    } catch (error) {
      logger.error('Error incrementing rate limit:', error);
      return 1;
    }
  }

  /**
   * Cache session data
   * @param {string} sessionId - Session ID
   * @param {Object} sessionData - Session data
   * @param {number} ttl - Time to live in seconds
   */
  static async setSession(sessionId, sessionData, ttl = 86400) { // 24 hours
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `session:${sessionId}`;
      await client.setEx(cacheKey, ttl, JSON.stringify(sessionData));
    } catch (error) {
      logger.error('Error setting session in cache:', error);
    }
  }

  /**
   * Get session data
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object|null>} - Session data or null
   */
  static async getSession(sessionId) {
    const client = this.getClient();
    if (!client) return null;

    try {
      const cacheKey = `session:${sessionId}`;
      const sessionData = await client.get(cacheKey);
      return sessionData ? JSON.parse(sessionData) : null;
    } catch (error) {
      logger.error('Error getting session from cache:', error);
      return null;
    }
  }

  /**
   * Delete session data
   * @param {string} sessionId - Session ID
   */
  static async deleteSession(sessionId) {
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `session:${sessionId}`;
      await client.del(cacheKey);
    } catch (error) {
      logger.error('Error deleting session from cache:', error);
    }
  }

  /**
   * Cache AI analysis results
   * @param {string} urlHash - Hash of the URL
   * @param {Object} analysis - AI analysis results
   * @param {number} ttl - Time to live in seconds
   */
  static async setAIAnalysis(urlHash, analysis, ttl = 86400) { // 24 hours
    const client = this.getClient();
    if (!client) return;

    try {
      const cacheKey = `ai_analysis:${urlHash}`;
      await client.setEx(cacheKey, ttl, JSON.stringify(analysis));
      logger.debug(`Cached AI analysis: ${urlHash}`);
    } catch (error) {
      logger.error('Error caching AI analysis:', error);
    }
  }

  /**
   * Get AI analysis results
   * @param {string} urlHash - Hash of the URL
   * @returns {Promise<Object|null>} - AI analysis or null
   */
  static async getAIAnalysis(urlHash) {
    const client = this.getClient();
    if (!client) return null;

    try {
      const cacheKey = `ai_analysis:${urlHash}`;
      const analysis = await client.get(cacheKey);
      
      if (analysis) {
        logger.debug(`AI analysis cache hit: ${urlHash}`);
        return JSON.parse(analysis);
      }
      
      return null;
    } catch (error) {
      logger.error('Error getting AI analysis from cache:', error);
      return null;
    }
  }

  /**
   * Get cache statistics
   * @returns {Promise<Object>} - Cache statistics
   */
  static async getStats() {
    const client = this.getClient();
    if (!client) {
      return { connected: false };
    }

    try {
      const info = await client.info('memory');
      const keyspace = await client.info('keyspace');
      
      return {
        connected: true,
        memory: info,
        keyspace: keyspace
      };
    } catch (error) {
      logger.error('Error getting cache stats:', error);
      return { connected: false, error: error.message };
    }
  }

  /**
   * Clear all cache data (use with caution)
   */
  static async clearAll() {
    const client = this.getClient();
    if (!client) return;

    try {
      await client.flushAll();
      logger.warn('All cache data cleared');
    } catch (error) {
      logger.error('Error clearing cache:', error);
    }
  }
}

module.exports = CacheService; 