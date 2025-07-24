const express = require('express');
const { query, param, body, validationResult } = require('express-validator');
const User = require('../models/User');
const URLMapping = require('../models/URLMapping');
const ClickEvent = require('../models/ClickEvent');
const AnalyticsService = require('../services/AnalyticsService');
const CacheService = require('../services/CacheService');
const logger = require('../utils/logger');

const router = express.Router();
const analyticsService = new AnalyticsService();
const cacheService = new CacheService();

/**
 * Validation middleware
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: errors.array()[0].msg
    });
  }
  next();
};

/**
 * GET /api/admin/dashboard
 * Get system-wide dashboard statistics
 */
router.get('/dashboard',
  async (req, res, next) => {
    try {
      const [
        totalUsers,
        activeUsers,
        totalUrls,
        activeUrls,
        totalClicks,
        todayClicks,
        systemStats
      ] = await Promise.all([
        User.countDocuments({}),
        User.countDocuments({ isActive: true }),
        URLMapping.countDocuments({}),
        URLMapping.countDocuments({ 
          isActive: true,
          $or: [
            { expiresAt: null },
            { expiresAt: { $gt: new Date() } }
          ]
        }),
        ClickEvent.countDocuments({ 'fraudDetection.isBot': { $ne: true } }),
        ClickEvent.countDocuments({
          timestamp: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) },
          'fraudDetection.isBot': { $ne: true }
        }),
        getSystemStats()
      ]);

      // Get growth metrics (last 30 days)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const [newUsers, newUrls, newClicks] = await Promise.all([
        User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
        URLMapping.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
        ClickEvent.countDocuments({
          timestamp: { $gte: thirtyDaysAgo },
          'fraudDetection.isBot': { $ne: true }
        })
      ]);

      // Get cache stats
      const cacheStats = await cacheService.getStats();

      res.json({
        success: true,
        data: {
          overview: {
            users: {
              total: totalUsers,
              active: activeUsers,
              newThisMonth: newUsers
            },
            urls: {
              total: totalUrls,
              active: activeUrls,
              newThisMonth: newUrls
            },
            clicks: {
              total: totalClicks,
              today: todayClicks,
              thisMonth: newClicks
            }
          },
          system: systemStats,
          cache: cacheStats
        }
      });

    } catch (error) {
      logger.error('Error getting admin dashboard:', error);
      next(error);
    }
  }
);

/**
 * GET /api/admin/users
 * Get user management data
 */
router.get('/users',
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('search')
      .optional()
      .isLength({ max: 100 })
      .withMessage('Search term too long'),
    query('role')
      .optional()
      .isIn(['user', 'premium', 'admin'])
      .withMessage('Invalid role filter'),
    query('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        role,
        isActive
      } = req.query;

      const query = {};

      if (search) {
        query.$or = [
          { username: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { firstName: { $regex: search, $options: 'i' } },
          { lastName: { $regex: search, $options: 'i' } }
        ];
      }

      if (role) {
        query.role = role;
      }

      if (isActive !== undefined) {
        query.isActive = isActive === 'true';
      }

      const users = await User.find(query)
        .select('-password -refreshTokens')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit))
        .lean();

      const total = await User.countDocuments(query);

      // Get additional stats for each user
      const usersWithStats = await Promise.all(
        users.map(async (user) => {
          const [urlCount, totalClicks] = await Promise.all([
            URLMapping.countDocuments({ userId: user._id }),
            URLMapping.aggregate([
              { $match: { userId: user._id } },
              { $group: { _id: null, total: { $sum: '$clickCount' } } }
            ])
          ]);

          return {
            ...user,
            stats: {
              urlCount,
              totalClicks: totalClicks[0]?.total || 0
            }
          };
        })
      );

      res.json({
        success: true,
        data: usersWithStats,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });

    } catch (error) {
      logger.error('Error getting users:', error);
      next(error);
    }
  }
);

/**
 * PUT /api/admin/users/:userId
 * Update user (admin only)
 */
router.put('/users/:userId',
  [
    param('userId')
      .isMongoId()
      .withMessage('Invalid user ID'),
    body('role')
      .optional()
      .isIn(['user', 'premium', 'admin'])
      .withMessage('Invalid role'),
    body('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be boolean'),
    body('subscription.plan')
      .optional()
      .isIn(['free', 'basic', 'premium', 'enterprise'])
      .withMessage('Invalid subscription plan'),
    body('limits.dailyUrls')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Daily URL limit must be non-negative'),
    body('limits.monthlyUrls')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Monthly URL limit must be non-negative')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { userId } = req.params;
      const updates = req.body;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Apply updates
      if (updates.role !== undefined) {
        user.role = updates.role;
      }

      if (updates.isActive !== undefined) {
        user.isActive = updates.isActive;
      }

      if (updates.subscription) {
        Object.assign(user.subscription, updates.subscription);
      }

      if (updates.limits) {
        Object.assign(user.limits, updates.limits);
      }

      await user.save();

      logger.info(`User updated by admin: ${user.username}`, {
        adminId: req.user._id,
        targetUserId: userId,
        updates
      });

      res.json({
        success: true,
        message: 'User updated successfully',
        data: user
      });

    } catch (error) {
      logger.error('Error updating user:', error);
      next(error);
    }
  }
);

/**
 * GET /api/admin/urls
 * Get URL management data
 */
router.get('/urls',
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('search')
      .optional()
      .isLength({ max: 100 })
      .withMessage('Search term too long'),
    query('aiVerdict')
      .optional()
      .isIn(['safe', 'suspicious', 'malicious', 'pending'])
      .withMessage('Invalid AI verdict filter'),
    query('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        aiVerdict,
        isActive
      } = req.query;

      const query = {};

      if (search) {
        query.$or = [
          { shortId: { $regex: search, $options: 'i' } },
          { longUrl: { $regex: search, $options: 'i' } },
          { title: { $regex: search, $options: 'i' } }
        ];
      }

      if (aiVerdict) {
        query['meta.aiSpamVerdict'] = aiVerdict;
      }

      if (isActive !== undefined) {
        query.isActive = isActive === 'true';
      }

      const urls = await URLMapping.find(query)
        .populate('userId', 'username email')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit))
        .lean();

      const total = await URLMapping.countDocuments(query);

      res.json({
        success: true,
        data: urls,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });

    } catch (error) {
      logger.error('Error getting URLs:', error);
      next(error);
    }
  }
);

/**
 * PUT /api/admin/urls/:shortId
 * Update URL (admin only)
 */
router.put('/urls/:shortId',
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format'),
    body('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be boolean'),
    body('meta.aiSpamVerdict')
      .optional()
      .isIn(['safe', 'suspicious', 'malicious', 'pending'])
      .withMessage('Invalid AI spam verdict')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;
      const updates = req.body;

      const urlMapping = await URLMapping.findOne({ shortId });
      if (!urlMapping) {
        return res.status(404).json({
          success: false,
          error: 'URL not found'
        });
      }

      // Apply updates
      if (updates.isActive !== undefined) {
        urlMapping.isActive = updates.isActive;
      }

      if (updates.meta) {
        Object.assign(urlMapping.meta, updates.meta);
      }

      await urlMapping.save();

      logger.info(`URL updated by admin: ${shortId}`, {
        adminId: req.user._id,
        shortId,
        updates
      });

      res.json({
        success: true,
        message: 'URL updated successfully',
        data: urlMapping
      });

    } catch (error) {
      logger.error('Error updating URL:', error);
      next(error);
    }
  }
);

/**
 * GET /api/admin/analytics
 * Get system-wide analytics
 */
router.get('/analytics',
  [
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
      const {
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        groupBy = 'day'
      } = req.query;

      const [
        clicksOverTime,
        topUrls,
        topCountries,
        deviceBreakdown,
        fraudStats
      ] = await Promise.all([
        // System-wide clicks over time
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
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

        // Top URLs system-wide
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
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
          { $limit: 20 }
        ]),

        // Top countries
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
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
          { $limit: 15 }
        ]),

        // Device breakdown
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
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

        // Fraud statistics
        ClickEvent.aggregate([
          {
            $match: {
              timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) }
            }
          },
          {
            $group: {
              _id: null,
              totalClicks: { $sum: 1 },
              botClicks: { $sum: { $cond: ['$fraudDetection.isBot', 1, 0] } },
              suspiciousClicks: { $sum: { $cond: ['$fraudDetection.isSuspicious', 1, 0] } },
              avgRiskScore: { $avg: '$fraudDetection.riskScore' }
            }
          }
        ])
      ]);

      res.json({
        success: true,
        data: {
          timeSeries: clicksOverTime,
          topUrls,
          geography: topCountries,
          devices: deviceBreakdown,
          fraud: fraudStats[0] || {
            totalClicks: 0,
            botClicks: 0,
            suspiciousClicks: 0,
            avgRiskScore: 0
          },
          period: {
            start: startDate,
            end: endDate
          }
        }
      });

    } catch (error) {
      logger.error('Error getting system analytics:', error);
      next(error);
    }
  }
);

/**
 * POST /api/admin/system/cache/clear
 * Clear system cache
 */
router.post('/system/cache/clear',
  async (req, res, next) => {
    try {
      await cacheService.clearAll();

      logger.info('System cache cleared by admin', {
        adminId: req.user._id
      });

      res.json({
        success: true,
        message: 'Cache cleared successfully'
      });

    } catch (error) {
      logger.error('Error clearing cache:', error);
      next(error);
    }
  }
);

/**
 * GET /api/admin/system/health
 * Get system health status
 */
router.get('/system/health',
  async (req, res, next) => {
    try {
      const health = await getSystemHealth();

      res.json({
        success: true,
        data: health
      });

    } catch (error) {
      logger.error('Error getting system health:', error);
      next(error);
    }
  }
);

/**
 * Helper function to get system statistics
 */
async function getSystemStats() {
  return {
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    platform: process.platform,
    nodeVersion: process.version,
    pid: process.pid
  };
}

/**
 * Helper function to get system health
 */
async function getSystemHealth() {
  const mongoose = require('mongoose');
  
  const health = {
    status: 'healthy',
    timestamp: new Date(),
    services: {
      database: {
        status: 'unknown',
        responseTime: null
      },
      cache: {
        status: 'unknown',
        responseTime: null
      }
    }
  };

  // Check MongoDB health
  try {
    const start = Date.now();
    await mongoose.connection.db.admin().ping();
    health.services.database.status = 'healthy';
    health.services.database.responseTime = Date.now() - start;
  } catch (error) {
    health.services.database.status = 'unhealthy';
    health.services.database.error = error.message;
    health.status = 'degraded';
  }

  // Check Redis health
  try {
    const start = Date.now();
    const stats = await cacheService.getStats();
    health.services.cache.status = stats.connected ? 'healthy' : 'unhealthy';
    health.services.cache.responseTime = Date.now() - start;
    
    if (!stats.connected) {
      health.status = 'degraded';
    }
  } catch (error) {
    health.services.cache.status = 'unhealthy';
    health.services.cache.error = error.message;
    health.status = 'degraded';
  }

  return health;
}

module.exports = router; 