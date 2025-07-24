const crypto = require('crypto');
const geoip = require('geoip-lite');
const useragent = require('useragent');
const ClickEvent = require('../models/ClickEvent');
const CacheService = require('./CacheService');
const logger = require('../utils/logger');

class AnalyticsService {
  constructor() {
    this.cacheService = new CacheService();
  }

  /**
   * Hash IP address for privacy
   * @param {string} ip - IP address
   * @returns {string} - Hashed IP
   */
  static hashIp(ip) {
    return crypto.createHash('sha256').update(ip + process.env.IP_SALT || 'default-salt').digest('hex');
  }

  /**
   * Parse user agent information
   * @param {string} userAgentString - User agent string
   * @returns {Object} - Parsed user agent info
   */
  static parseUserAgent(userAgentString) {
    const agent = useragent.parse(userAgentString);
    
    return {
      browser: agent.toAgent(),
      os: agent.os.toString(),
      device: AnalyticsService.detectDeviceType(userAgentString),
      family: agent.family,
      major: agent.major,
      minor: agent.minor
    };
  }

  /**
   * Detect device type from user agent
   * @param {string} userAgent - User agent string
   * @returns {string} - Device type
   */
  static detectDeviceType(userAgent) {
    const ua = userAgent.toLowerCase();
    
    if (/bot|crawler|spider|scraper/i.test(userAgent)) {
      return 'bot';
    }
    
    if (/mobile|android|iphone|ipod|blackberry|iemobile|opera mini/i.test(ua)) {
      return 'mobile';
    }
    
    if (/tablet|ipad|android(?!.*mobile)/i.test(ua)) {
      return 'tablet';
    }
    
    return 'desktop';
  }

  /**
   * Get geographic information from IP
   * @param {string} ip - IP address
   * @returns {Object} - Geographic information
   */
  static getGeoLocation(ip) {
    try {
      const geo = geoip.lookup(ip);
      
      if (!geo) {
        return {
          country: 'Unknown',
          region: 'Unknown',
          city: 'Unknown',
          timezone: 'Unknown',
          coordinates: null
        };
      }

      return {
        country: geo.country || 'Unknown',
        region: geo.region || 'Unknown',
        city: geo.city || 'Unknown',
        timezone: geo.timezone || 'Unknown',
        coordinates: geo.ll ? {
          lat: geo.ll[0],
          lon: geo.ll[1]
        } : null
      };
    } catch (error) {
      logger.error('Error getting geo location:', error);
      return {
        country: 'Unknown',
        region: 'Unknown',
        city: 'Unknown',
        timezone: 'Unknown',
        coordinates: null
      };
    }
  }

  /**
   * Generate session ID based on IP and user agent
   * @param {string} ip - IP address
   * @param {string} userAgent - User agent string
   * @returns {string} - Session ID
   */
  static generateSessionId(ip, userAgent) {
    const sessionData = `${ip}-${userAgent}-${new Date().toDateString()}`;
    return crypto.createHash('md5').update(sessionData).digest('hex');
  }

  /**
   * Check if this is a unique click for the URL
   * @param {string} shortId - Short ID
   * @param {string} hashedIp - Hashed IP address
   * @param {string} sessionId - Session ID
   * @returns {Promise<boolean>} - True if unique
   */
  static async isUniqueClick(shortId, hashedIp, sessionId) {
    try {
      // Check if we've seen this IP/session combo for this URL in the last 24 hours
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      const existingClick = await ClickEvent.findOne({
        shortId,
        $or: [
          { hashedIp, timestamp: { $gte: oneDayAgo } },
          { sessionId, timestamp: { $gte: oneDayAgo } }
        ]
      });

      return !existingClick;
    } catch (error) {
      logger.error('Error checking unique click:', error);
      return false;
    }
  }

  /**
   * Extract UTM campaign parameters
   * @param {string} referrer - Referrer URL
   * @returns {Object} - Campaign parameters
   */
  static extractCampaignData(referrer) {
    if (!referrer) {
      return {
        source: null,
        medium: null,
        campaign: null,
        term: null,
        content: null
      };
    }

    try {
      const url = new URL(referrer);
      const params = url.searchParams;

      return {
        source: params.get('utm_source'),
        medium: params.get('utm_medium'),
        campaign: params.get('utm_campaign'),
        term: params.get('utm_term'),
        content: params.get('utm_content')
      };
    } catch (error) {
      return {
        source: null,
        medium: null,
        campaign: null,
        term: null,
        content: null
      };
    }
  }

  /**
   * Record a click event
   * @param {string} shortId - Short ID
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} - Created click event
   */
  async recordClick(shortId, req) {
    try {
      // Extract data from request
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      const userAgent = req.get('User-Agent') || 'unknown';
      const referrer = req.get('Referer') || null;
      const userId = req.user?.id || null;

      // Hash IP for privacy
      const hashedIp = AnalyticsService.hashIp(ip);
      
      // Parse user agent
      const deviceInfo = AnalyticsService.parseUserAgent(userAgent);
      
      // Get geographic information
      const geoLocation = AnalyticsService.getGeoLocation(ip);
      
      // Generate session ID
      const sessionId = AnalyticsService.generateSessionId(ip, userAgent);
      
      // Check if this is a unique click
      const isUnique = await AnalyticsService.isUniqueClick(shortId, hashedIp, sessionId);
      
      // Extract campaign data
      const campaign = AnalyticsService.extractCampaignData(referrer);

      // Get URL mapping to get the urlMappingId
      const URLMapping = require('../models/URLMapping');
      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        throw new Error('URL mapping not found');
      }

      // Create click event
      const clickEvent = new ClickEvent({
        shortId,
        urlMappingId: urlMapping._id,
        ip,
        hashedIp,
        userAgent,
        referrer,
        geoLocation,
        device: {
          type: deviceInfo.device,
          browser: deviceInfo.browser,
          os: deviceInfo.os,
          brand: null,
          model: null
        },
        sessionId,
        userId,
        isUnique,
        performance: {
          loadTime: null,
          redirectTime: null,
          dnsTime: null
        },
        campaign,
        metadata: {
          language: null,
          screenResolution: null,
          colorDepth: null,
          timezoneOffset: null,
          plugins: []
        }
      });

      // Basic fraud detection
      clickEvent.calculateFraudScore();

      // Save click event
      await clickEvent.save();

      logger.debug(`Click recorded: ${shortId}`, {
        isUnique,
        device: deviceInfo.device,
        country: geoLocation.country,
        isBot: clickEvent.fraudDetection.isBot
      });

      return clickEvent;

    } catch (error) {
      logger.error('Error recording click:', error);
      throw error;
    }
  }

  /**
   * Get analytics for a URL
   * @param {string} shortId - Short ID
   * @param {Object} options - Analytics options
   * @returns {Promise<Object>} - Analytics data
   */
  async getUrlAnalytics(shortId, options = {}) {
    try {
      const {
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
        endDate = new Date(),
        includeRealTime = false,
        includeFraud = false
      } = options;

      const cacheKey = `${shortId}-${startDate.toISOString()}-${endDate.toISOString()}`;
      
      // Check cache first
      const cachedAnalytics = await this.cacheService.getAnalytics(cacheKey);
      if (cachedAnalytics && !includeRealTime) {
        return cachedAnalytics;
      }

      // Get basic statistics
      const [
        totalClicks,
        uniqueClicks,
        timeSeriesData,
        topCountries,
        deviceStats,
        referrerStats,
        fraudStats
      ] = await Promise.all([
        this.getTotalClicks(shortId, startDate, endDate),
        this.getUniqueClicks(shortId, startDate, endDate),
        this.getTimeSeriesData(shortId, startDate, endDate),
        this.getTopCountries(shortId, startDate, endDate),
        this.getDeviceStats(shortId, startDate, endDate),
        this.getReferrerStats(shortId, startDate, endDate),
        includeFraud ? this.getFraudStats(shortId, startDate, endDate) : null
      ]);

      const analytics = {
        summary: {
          totalClicks,
          uniqueClicks,
          clickThroughRate: uniqueClicks > 0 ? (totalClicks / uniqueClicks).toFixed(2) : 0,
          period: {
            start: startDate,
            end: endDate
          }
        },
        timeSeries: timeSeriesData,
        geography: topCountries,
        devices: deviceStats,
        referrers: referrerStats,
        fraud: fraudStats,
        generatedAt: new Date()
      };

      // Cache the results (skip if real-time data requested)
      if (!includeRealTime) {
        await this.cacheService.setAnalytics(cacheKey, analytics);
      }

      return analytics;

    } catch (error) {
      logger.error('Error getting URL analytics:', error);
      throw error;
    }
  }

  /**
   * Get total clicks for a URL
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<number>} - Total clicks
   */
  async getTotalClicks(shortId, startDate, endDate) {
    return ClickEvent.countDocuments({
      shortId,
      timestamp: { $gte: startDate, $lte: endDate },
      'fraudDetection.isBot': { $ne: true }
    });
  }

  /**
   * Get unique clicks for a URL
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<number>} - Unique clicks
   */
  async getUniqueClicks(shortId, startDate, endDate) {
    return ClickEvent.countDocuments({
      shortId,
      timestamp: { $gte: startDate, $lte: endDate },
      isUnique: true,
      'fraudDetection.isBot': { $ne: true }
    });
  }

  /**
   * Get time series data
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Array>} - Time series data
   */
  async getTimeSeriesData(shortId, startDate, endDate) {
    return ClickEvent.getAnalytics(shortId, {
      startDate,
      endDate,
      groupBy: 'day'
    });
  }

  /**
   * Get top countries
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Array>} - Top countries
   */
  async getTopCountries(shortId, startDate, endDate) {
    return ClickEvent.aggregate([
      {
        $match: {
          shortId,
          timestamp: { $gte: startDate, $lte: endDate },
          'fraudDetection.isBot': { $ne: true },
          'geoLocation.country': { $exists: true, $ne: 'Unknown' }
        }
      },
      {
        $group: {
          _id: '$geoLocation.country',
          clicks: { $sum: 1 },
          uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
        }
      },
      { $sort: { clicks: -1 } },
      { $limit: 10 }
    ]);
  }

  /**
   * Get device statistics
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Array>} - Device statistics
   */
  async getDeviceStats(shortId, startDate, endDate) {
    return ClickEvent.aggregate([
      {
        $match: {
          shortId,
          timestamp: { $gte: startDate, $lte: endDate },
          'fraudDetection.isBot': { $ne: true }
        }
      },
      {
        $group: {
          _id: {
            type: '$device.type',
            browser: '$device.browser',
            os: '$device.os'
          },
          clicks: { $sum: 1 },
          uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
        }
      },
      { $sort: { clicks: -1 } }
    ]);
  }

  /**
   * Get referrer statistics
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Array>} - Referrer statistics
   */
  async getReferrerStats(shortId, startDate, endDate) {
    return ClickEvent.aggregate([
      {
        $match: {
          shortId,
          timestamp: { $gte: startDate, $lte: endDate },
          'fraudDetection.isBot': { $ne: true },
          referrer: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: '$referrer',
          clicks: { $sum: 1 },
          uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
        }
      },
      { $sort: { clicks: -1 } },
      { $limit: 20 }
    ]);
  }

  /**
   * Get fraud statistics
   * @param {string} shortId - Short ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} - Fraud statistics
   */
  async getFraudStats(shortId, startDate, endDate) {
    const [totalFraud, botClicks, suspiciousClicks] = await Promise.all([
      ClickEvent.countDocuments({
        shortId,
        timestamp: { $gte: startDate, $lte: endDate },
        'fraudDetection.isSuspicious': true
      }),
      ClickEvent.countDocuments({
        shortId,
        timestamp: { $gte: startDate, $lte: endDate },
        'fraudDetection.isBot': true
      }),
      ClickEvent.aggregate([
        {
          $match: {
            shortId,
            timestamp: { $gte: startDate, $lte: endDate },
            'fraudDetection.isSuspicious': true
          }
        },
        {
          $group: {
            _id: '$fraudDetection.fraudReasons',
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    return {
      totalFraudulent: totalFraud,
      botClicks,
      suspiciousReasons: suspiciousClicks
    };
  }

  /**
   * Get real-time analytics
   * @param {string} shortId - Short ID
   * @param {number} hours - Hours to look back
   * @returns {Promise<Object>} - Real-time analytics
   */
  async getRealTimeAnalytics(shortId, hours = 24) {
    try {
      const startDate = new Date(Date.now() - hours * 60 * 60 * 1000);
      
      const [recentClicks, hourlyData] = await Promise.all([
        ClickEvent.find({
          shortId,
          timestamp: { $gte: startDate },
          'fraudDetection.isBot': { $ne: true }
        })
        .sort({ timestamp: -1 })
        .limit(100)
        .lean(),
        
        ClickEvent.getAnalytics(shortId, {
          startDate,
          endDate: new Date(),
          groupBy: 'hour'
        })
      ]);

      return {
        recentClicks: recentClicks.length,
        hourlyBreakdown: hourlyData,
        lastUpdated: new Date()
      };

    } catch (error) {
      logger.error('Error getting real-time analytics:', error);
      throw error;
    }
  }

  /**
   * Clean up old analytics data
   * @param {number} daysToKeep - Days of data to keep
   * @returns {Promise<number>} - Number of records deleted
   */
  async cleanupOldData(daysToKeep = 730) { // 2 years default
    try {
      const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
      
      const result = await ClickEvent.deleteMany({
        timestamp: { $lt: cutoffDate }
      });

      logger.info(`Cleaned up ${result.deletedCount} old click events`);
      return result.deletedCount;

    } catch (error) {
      logger.error('Error cleaning up old data:', error);
      throw error;
    }
  }
}

module.exports = AnalyticsService; 