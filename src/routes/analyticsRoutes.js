const express = require('express');
const { param, query, validationResult } = require('express-validator');
const AnalyticsService = require('../services/AnalyticsService');
const ClickEvent = require('../models/ClickEvent');
const URLMapping = require('../models/URLMapping');
const authMiddleware = require('../middleware/auth');
const rateLimitMiddleware = require('../middleware/rateLimit');
const logger = require('../utils/logger');

const router = express.Router();
const analyticsService = new AnalyticsService();

/**
 * Validation middleware
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      details: errors.array()
    });
  }
  next();
};

/**
 * GET /api/analytics/dashboard
 * Get user's dashboard analytics
 */
router.get('/dashboard',
  authMiddleware.authenticate,
  rateLimitMiddleware.analyticsLimiter,
  [
    query('period')
      .optional()
      .isIn(['today', 'week', 'month', 'year'])
      .withMessage('Period must be one of: today, week, month, year'),
    query('includeRealTime')
      .optional()
      .isBoolean()
      .withMessage('includeRealTime must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { period = 'month', includeRealTime = false } = req.query;
      const userId = req.user._id;

      // Calculate date range based on period
      let startDate;
      const endDate = new Date();

      switch (period) {
        case 'today':
          startDate = new Date();
          startDate.setHours(0, 0, 0, 0);
          break;
        case 'week':
          startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'month':
          startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          break;
        case 'year':
          startDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      }

      // Get user's URLs
      const userUrls = await URLMapping.find({ userId }).select('shortId');
      const shortIds = userUrls.map(url => url.shortId);

      if (shortIds.length === 0) {
        return res.json({
          success: true,
          data: {
            summary: {
              totalUrls: 0,
              totalClicks: 0,
              uniqueClicks: 0,
              clickThroughRate: 0
            },
            charts: {
              clicksOverTime: [],
              topUrls: [],
              topCountries: [],
              deviceBreakdown: []
            }
          }
        });
      }

      // Get aggregated analytics for all user's URLs
      const [
        totalClicks,
        uniqueClicks,
        clicksOverTime,
        topUrls,
        topCountries,
        deviceBreakdown,
        realTimeData
      ] = await Promise.all([
        // Total clicks
        ClickEvent.countDocuments({
          shortId: { $in: shortIds },
          timestamp: { $gte: startDate, $lte: endDate },
          'fraudDetection.isBot': { $ne: true }
        }),

        // Unique clicks
        ClickEvent.countDocuments({
          shortId: { $in: shortIds },
          timestamp: { $gte: startDate, $lte: endDate },
          isUnique: true,
          'fraudDetection.isBot': { $ne: true }
        }),

        // Clicks over time
        ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
              timestamp: { $gte: startDate, $lte: endDate },
              'fraudDetection.isBot': { $ne: true }
            }
          },
          {
            $group: {
              _id: {
                date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
              },
              clicks: { $sum: 1 },
              uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
            }
          },
          { $sort: { '_id.date': 1 } }
        ]),

        // Top URLs
        ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
              timestamp: { $gte: startDate, $lte: endDate },
              'fraudDetection.isBot': { $ne: true }
            }
          },
          {
            $group: {
              _id: '$shortId',
              clicks: { $sum: 1 },
              uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
            }
          },
          { $sort: { clicks: -1 } },
          { $limit: 10 }
        ]),

        // Top countries
        ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
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
        ]),

        // Device breakdown
        ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
              timestamp: { $gte: startDate, $lte: endDate },
              'fraudDetection.isBot': { $ne: true }
            }
          },
          {
            $group: {
              _id: '$device.type',
              clicks: { $sum: 1 },
              uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } }
            }
          },
          { $sort: { clicks: -1 } }
        ]),

        // Real-time data (last 24 hours)
        includeRealTime === 'true' ? ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
              timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
              'fraudDetection.isBot': { $ne: true }
            }
          },
          {
            $group: {
              _id: {
                hour: { $dateToString: { format: '%Y-%m-%d-%H', date: '$timestamp' } }
              },
              clicks: { $sum: 1 }
            }
          },
          { $sort: { '_id.hour': 1 } }
        ]) : null
      ]);

      const dashboard = {
        summary: {
          totalUrls: userUrls.length,
          totalClicks,
          uniqueClicks,
          clickThroughRate: totalClicks > 0 ? (uniqueClicks / totalClicks * 100).toFixed(2) : 0,
          period: {
            start: startDate,
            end: endDate,
            label: period
          }
        },
        charts: {
          clicksOverTime,
          topUrls,
          topCountries,
          deviceBreakdown
        }
      };

      if (realTimeData) {
        dashboard.realTime = realTimeData;
      }

      res.json({
        success: true,
        data: dashboard
      });

    } catch (error) {
      logger.error('Error getting dashboard analytics:', error);
      next(error);
    }
  }
);

/**
 * GET /api/analytics/url/:shortId/detailed
 * Get detailed analytics for a specific URL
 */
router.get('/url/:shortId/detailed',
  authMiddleware.authenticate,
  rateLimitMiddleware.analyticsLimiter,
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format'),
    query('startDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid start date format'),
    query('endDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid end date format'),
    query('groupBy')
      .optional()
      .isIn(['hour', 'day', 'week', 'month'])
      .withMessage('groupBy must be one of: hour, day, week, month')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;
      const {
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        groupBy = 'day'
      } = req.query;

      // Verify user has access to this URL
      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        return res.status(404).json({
          success: false,
          error: 'URL not found'
        });
      }

      const hasAccess = !urlMapping.userId || 
                       (req.user._id.toString() === urlMapping.userId.toString()) ||
                       req.user.role === 'admin';

      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to analytics for this URL'
        });
      }

      // Get detailed analytics
      const analytics = await analyticsService.getUrlAnalytics(shortId, {
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        includeRealTime: true,
        includeFraud: req.user.role === 'admin'
      });

      res.json({
        success: true,
        data: analytics
      });

    } catch (error) {
      logger.error('Error getting detailed URL analytics:', error);
      next(error);
    }
  }
);

/**
 * GET /api/analytics/real-time
 * Get real-time analytics for user's URLs
 */
router.get('/real-time',
  authMiddleware.authenticate,
  rateLimitMiddleware.analyticsLimiter,
  [
    query('hours')
      .optional()
      .isInt({ min: 1, max: 72 })
      .withMessage('Hours must be between 1 and 72')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { hours = 24 } = req.query;
      const userId = req.user._id;

      // Get user's URLs
      const userUrls = await URLMapping.find({ userId }).select('shortId');
      const shortIds = userUrls.map(url => url.shortId);

      if (shortIds.length === 0) {
        return res.json({
          success: true,
          data: {
            activeUrls: 0,
            recentClicks: [],
            hourlyBreakdown: []
          }
        });
      }

      const startDate = new Date(Date.now() - hours * 60 * 60 * 1000);

      const [recentClicks, hourlyData] = await Promise.all([
        // Recent clicks
        ClickEvent.find({
          shortId: { $in: shortIds },
          timestamp: { $gte: startDate },
          'fraudDetection.isBot': { $ne: true }
        })
        .sort({ timestamp: -1 })
        .limit(50)
        .select('shortId timestamp geoLocation.country device.type referrer')
        .lean(),

        // Hourly breakdown
        ClickEvent.aggregate([
          {
            $match: {
              shortId: { $in: shortIds },
              timestamp: { $gte: startDate },
              'fraudDetection.isBot': { $ne: true }
            }
          },
          {
            $group: {
              _id: {
                hour: { $dateToString: { format: '%Y-%m-%d-%H', date: '$timestamp' } },
                shortId: '$shortId'
              },
              clicks: { $sum: 1 }
            }
          },
          {
            $group: {
              _id: '$_id.hour',
              totalClicks: { $sum: '$clicks' },
              activeUrls: { $sum: 1 }
            }
          },
          { $sort: { _id: 1 } }
        ])
      ]);

      res.json({
        success: true,
        data: {
          activeUrls: shortIds.length,
          recentClicks,
          hourlyBreakdown: hourlyData,
          period: {
            hours,
            start: startDate,
            end: new Date()
          }
        }
      });

    } catch (error) {
      logger.error('Error getting real-time analytics:', error);
      next(error);
    }
  }
);

/**
 * GET /api/analytics/export
 * Export analytics data
 */
router.get('/export',
  authMiddleware.authenticate,
  authMiddleware.requirePremiumFeature('analytics'),
  [
    query('shortId')
      .optional()
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format'),
    query('startDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid start date format'),
    query('endDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid end date format'),
    query('format')
      .optional()
      .isIn(['json', 'csv'])
      .withMessage('Format must be json or csv')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const {
        shortId,
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        format = 'json'
      } = req.query;

      let shortIds;
      if (shortId) {
        // Verify user has access to this specific URL
        const urlMapping = await URLMapping.findOne({ shortId });
        if (!urlMapping) {
          return res.status(404).json({
            success: false,
            error: 'URL not found'
          });
        }

        const hasAccess = !urlMapping.userId || 
                         (req.user._id.toString() === urlMapping.userId.toString()) ||
                         req.user.role === 'admin';

        if (!hasAccess) {
          return res.status(403).json({
            success: false,
            error: 'Access denied'
          });
        }

        shortIds = [shortId];
      } else {
        // Get all user's URLs
        const userUrls = await URLMapping.find({ userId: req.user._id }).select('shortId');
        shortIds = userUrls.map(url => url.shortId);
      }

      // Get click events
      const clickEvents = await ClickEvent.find({
        shortId: { $in: shortIds },
        timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
        'fraudDetection.isBot': { $ne: true }
      })
      .select('shortId timestamp geoLocation device referrer isUnique')
      .lean();

      if (format === 'csv') {
        // Convert to CSV
        const csvHeader = 'shortId,timestamp,country,region,city,deviceType,browser,os,referrer,isUnique\n';
        const csvRows = clickEvents.map(event => [
          event.shortId,
          event.timestamp.toISOString(),
          event.geoLocation?.country || '',
          event.geoLocation?.region || '',
          event.geoLocation?.city || '',
          event.device?.type || '',
          event.device?.browser || '',
          event.device?.os || '',
          event.referrer || '',
          event.isUnique
        ].join(',')).join('\n');

        const csvContent = csvHeader + csvRows;

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="analytics-${Date.now()}.csv"`);
        res.send(csvContent);
      } else {
        // Return JSON
        res.json({
          success: true,
          data: {
            period: {
              start: startDate,
              end: endDate
            },
            totalEvents: clickEvents.length,
            events: clickEvents
          }
        });
      }

    } catch (error) {
      logger.error('Error exporting analytics:', error);
      next(error);
    }
  }
);

/**
 * GET /api/analytics/fraud
 * Get fraud detection analytics (admin only)
 */
router.get('/fraud',
  authMiddleware.authenticate,
  authMiddleware.requireRole('admin'),
  [
    query('startDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid start date format'),
    query('endDate')
      .optional()
      .isISO8601()
      .withMessage('Invalid end date format'),
    query('threshold')
      .optional()
      .isFloat({ min: 0, max: 1 })
      .withMessage('Threshold must be between 0 and 1')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const {
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        threshold = 0.5
      } = req.query;

      const [
        totalFraudulent,
        botClicks,
        suspiciousClicks,
        fraudPatterns,
        topOffenders
      ] = await Promise.all([
        // Total fraudulent clicks
        ClickEvent.countDocuments({
          timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
          'fraudDetection.riskScore': { $gte: parseFloat(threshold) }
        }),

        // Bot clicks
        ClickEvent.countDocuments({
          timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
          'fraudDetection.isBot': true
        }),

        // Suspicious clicks by reason
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
              'fraudDetection.isSuspicious': true
            }
          },
          { $unwind: '$fraudDetection.fraudReasons' },
          {
            $group: {
              _id: '$fraudDetection.fraudReasons',
              count: { $sum: 1 }
            }
          },
          { $sort: { count: -1 } }
        ]),

        // Fraud patterns over time
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
              'fraudDetection.riskScore': { $gte: parseFloat(threshold) }
            }
          },
          {
            $group: {
              _id: {
                date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
              },
              fraudulentClicks: { $sum: 1 },
              avgRiskScore: { $avg: '$fraudDetection.riskScore' }
            }
          },
          { $sort: { '_id.date': 1 } }
        ]),

        // Top offending IPs/patterns
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
              'fraudDetection.riskScore': { $gte: parseFloat(threshold) }
            }
          },
          {
            $group: {
              _id: '$hashedIp',
              fraudulentClicks: { $sum: 1 },
              avgRiskScore: { $avg: '$fraudDetection.riskScore' },
              userAgents: { $addToSet: '$userAgent' }
            }
          },
          { $sort: { fraudulentClicks: -1 } },
          { $limit: 20 }
        ])
      ]);

      res.json({
        success: true,
        data: {
          summary: {
            totalFraudulent,
            botClicks,
            fraudRate: ((totalFraudulent / Math.max(totalFraudulent + botClicks, 1)) * 100).toFixed(2),
            period: {
              start: startDate,
              end: endDate
            }
          },
          breakdown: {
            suspiciousClicks,
            fraudPatterns,
            topOffenders
          }
        }
      });

    } catch (error) {
      logger.error('Error getting fraud analytics:', error);
      next(error);
    }
  }
);

/**
 * POST /api/analytics/cleanup
 * Clean up old analytics data (admin only)
 */
router.post('/cleanup',
  authMiddleware.authenticate,
  authMiddleware.requireRole('admin'),
  [
    query('daysToKeep')
      .optional()
      .isInt({ min: 30, max: 3650 })
      .withMessage('Days to keep must be between 30 and 3650')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { daysToKeep = 730 } = req.query; // 2 years default

      const deletedCount = await analyticsService.cleanupOldData(parseInt(daysToKeep));

      res.json({
        success: true,
        message: 'Analytics cleanup completed',
        data: {
          deletedEvents: deletedCount,
          daysToKeep: parseInt(daysToKeep)
        }
      });

    } catch (error) {
      logger.error('Error cleaning up analytics:', error);
      next(error);
    }
  }
);

module.exports = router; 