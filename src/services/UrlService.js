const QRCode = require('qrcode');
const logger = require('../utils/logger');
const URLMapping = require('../models/URLMapping');
const ClickEvent = require('../models/ClickEvent');
const CacheService = require('./CacheService');
const AIService = require('./AIService');
const AnalyticsService = require('./AnalyticsService');

class UrlService {
  // Add method to get nanoid dynamically
  static async getNanoid() {
    const { nanoid } = await import('nanoid');
    return nanoid;
  }

  static validateAndNormalizeUrl(url) {
    try {
      if (!/^https?:\/\//i.test(url)) {
        url = `https://${url}`;
      }

      const urlObj = new URL(url);
      
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        throw new Error('Only HTTP and HTTPS URLs are allowed');
      }

      if (this.containsSuspiciousPatterns(url)) {
        throw new Error('URL contains suspicious patterns');
      }

      return urlObj.href;
    } catch (error) {
      throw new Error(`Invalid URL: ${error.message}`);
    }
  }

  static containsSuspiciousPatterns(url) {
    const suspiciousPatterns = [
      /bit\.ly/i,
      /tinyurl/i,
      /t\.co/i,
      /localhost/i,
      /127\.0\.0\.1/i,
      /\d+\.\d+\.\d+\.\d+/,
      /\.tk$/i,
      /\.ml$/i,
      /\.ga$/i,
      /\.cf$/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(url));
  }

  static async shortenUrl(longUrl, userId, customAlias) {
    try {
      const aiAnalysisEnabled = process.env.AI_ANALYSIS_ENABLED === 'true';
      logger.info('Shortening URL', { longUrl, userId, customAlias });

      // Validate and normalize URL
      const normalizedUrl = this.validateAndNormalizeUrl(longUrl);

      // Generate short ID
      let shortId;
      if (customAlias) {
        // Check if custom alias is available
        const existingUrl = await URLMapping.findOne({ shortId: customAlias });
        if (existingUrl) {
          throw new Error('Custom alias already exists');
        }
        shortId = customAlias;
      } else {
        const nanoid = await this.getNanoid();
        shortId = nanoid(8);
      }

      // AI Analysis
      let aiAnalysis;
      if (aiAnalysisEnabled) {
        try {
          logger.info('Running AI analysis for URL', { longUrl: normalizedUrl });
          aiAnalysis = await AIService.analyzeUrl(normalizedUrl);
          
          // Block URL if AI determines it's malicious
          if (aiAnalysis.isBlocked) {
            logger.warn('URL blocked by AI analysis', { 
              longUrl: normalizedUrl, 
              reason: aiAnalysis.reason,
              safetyScore: aiAnalysis.safetyScore 
            });
            throw new Error(`URL blocked: ${aiAnalysis.reason}`);
          }
          
          logger.info('AI analysis completed', { 
            longUrl: normalizedUrl,
            safetyScore: aiAnalysis.safetyScore,
            isBlocked: aiAnalysis.isBlocked
          });
        } catch (aiError) {
          logger.error('AI analysis failed, using fallback', { 
            error: aiError.message, 
            longUrl: normalizedUrl 
          });
          
          // If it's a blocking error, re-throw it
          if (aiError.message.includes('blocked')) {
            throw aiError;
          }
          
          // Fallback to safe defaults for analysis failures
          aiAnalysis = {
            safetyScore: 0.8,
            isBlocked: false,
            reason: 'AI analysis unavailable',
            details: { error: aiError.message },
            analyzedAt: new Date().toISOString()
          };
        }
      } else {
        // AI analysis disabled - use neutral defaults
        aiAnalysis = {
          safetyScore: 0.9,
          isBlocked: false,
          reason: 'AI analysis disabled',
          details: {},
          analyzedAt: new Date().toISOString()
        };
      }

      // Create URL mapping
      const urlMapping = new URLMapping({
        shortId,
        longUrl: normalizedUrl,
        userId,
        metadata: {
          title: null,
          description: null,
          aiAnalysis: aiAnalysis
        }
      });

      await urlMapping.save();

      // Cache the mapping
      await CacheService.setUrlMapping(shortId, normalizedUrl);

      logger.info('URL shortened successfully', { shortId, longUrl: normalizedUrl });

      return {
        shortId,
        shortUrl: `${process.env.BASE_URL}/${shortId}`,
        longUrl: normalizedUrl,
        aiSafetyScore: aiAnalysis.safetyScore
      };
    } catch (error) {
      logger.error('Error shortening URL', { error: error.message, longUrl });
      throw error;
    }
  }

  static async getUrl(shortId) {
    try {
      // Try cache first
      const cachedUrl = await CacheService.getUrlMapping(shortId);
      if (cachedUrl) {
        return cachedUrl;
      }

      // Query database
      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        throw new Error('URL not found');
      }

      // Check if expired
      if (urlMapping.expiresAt && new Date() > urlMapping.expiresAt) {
        throw new Error('URL has expired');
      }

      // Cache for future requests
      await CacheService.setUrlMapping(shortId, urlMapping.longUrl);

      return urlMapping.longUrl;
    } catch (error) {
      logger.error('Error retrieving URL', { error: error.message, shortId });
      throw error;
    }
  }

  static async getUrlInfo(shortId) {
    try {
      // Query database for full information
      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        throw new Error('URL not found');
      }

      // Check if expired
      if (urlMapping.expiresAt && new Date() > urlMapping.expiresAt) {
        throw new Error('URL has expired');
      }

      return urlMapping;
    } catch (error) {
      logger.error('Error retrieving URL info', { error: error.message, shortId });
      throw error;
    }
  }

  static async trackClick(shortId, req) {
    try {
      const AnalyticsService = require('./AnalyticsService');
      const analyticsService = new AnalyticsService();
      const clickEvent = await analyticsService.recordClick(shortId, req);
      
      // Increment click counts - total count always, unique count only if it's unique
      const updateQuery = { $inc: { clickCount: 1 } };
      if (clickEvent.isUnique) {
        updateQuery.$inc.uniqueClickCount = 1;
      }
      
      await URLMapping.findOneAndUpdate(
        { shortId },
        updateQuery
      );

      logger.info('Click tracked', { 
        shortId, 
        isUnique: clickEvent.isUnique,
        totalClicks: true 
      });
    } catch (error) {
      logger.error('Error tracking click', { error: error.message, shortId });
    }
  }

  static async generateQRCode(shortId) {
    try {
      const fullUrl = `${process.env.BASE_URL}/${shortId}`;
      
      const qrCodeOptions = {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        quality: 0.92,
        margin: 1,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      };

      const qrCodeBuffer = await QRCode.toBuffer(fullUrl, qrCodeOptions);
      
      // Convert buffer to base64 data URL
      const base64String = qrCodeBuffer.toString('base64');
      const dataUrl = `data:image/png;base64,${base64String}`;
      
      return dataUrl;
    } catch (error) {
      logger.error('Error generating QR code', { error: error.message, shortId });
      throw new Error('Failed to generate QR code');
    }
  }

  static async getAnalytics(shortId, options = {}) {
    try {
      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        throw new Error('URL not found');
      }

      // Get basic analytics from the URL mapping
      const analytics = {
        shortId: urlMapping.shortId,
        longUrl: urlMapping.longUrl,
        totalClicks: urlMapping.clickCount || 0,
        uniqueClicks: urlMapping.uniqueClickCount || 0,
        createdAt: urlMapping.createdAt,
        lastClick: urlMapping.lastClickAt || null,
        // Additional analytics could be fetched from ClickEvent collection if needed
        topCountries: [],
        topDevices: []
      };

      return analytics;
    } catch (error) {
      logger.error('Error getting analytics', { error: error.message, shortId });
      throw error;
    }
  }

  static async getUserUrls(userId, page = 1, limit = 10) {
    try {
      const skip = (page - 1) * limit;
      
      const urls = await URLMapping.find({ userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('shortId longUrl createdAt analytics metadata expiresAt');

      const total = await URLMapping.countDocuments({ userId });

      return {
        urls,
        pagination: {
          current: page,
          total: Math.ceil(total / limit),
          count: urls.length,
          totalUrls: total
        }
      };
    } catch (error) {
      logger.error('Error getting user URLs', { error: error.message, userId });
      throw error;
    }
  }

  static async deleteUrl(shortId, userId) {
    try {
      const urlMapping = await URLMapping.findOne({ shortId, userId });
      if (!urlMapping) {
        throw new Error('URL not found or unauthorized');
      }

      await URLMapping.deleteOne({ shortId, userId });
      await CacheService.deleteUrlMapping(shortId);

      logger.info('URL deleted', { shortId, userId });
      return true;
    } catch (error) {
      logger.error('Error deleting URL', { error: error.message, shortId, userId });
      throw error;
    }
  }
}

module.exports = UrlService; 