const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const UrlService = require('../services/UrlService');
const authMiddleware = require('../middleware/auth');
const rateLimitMiddleware = require('../middleware/rateLimit');
const logger = require('../utils/logger');

const router = express.Router();
// Remove instance creation since we're using static methods
// const urlService = new UrlService();

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
 * POST /api/urls/shorten
 * Create a shortened URL
 */
router.post('/shorten',
  authMiddleware.optionalAuth,
  authMiddleware.checkUsageLimits,
  rateLimitMiddleware.urlShorteningLimiter,
  [
    body('longUrl')
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Valid URL is required')
      .isLength({ max: 2048 })
      .withMessage('URL too long'),
    body('customAlias')
      .optional()
      .isLength({ min: 3, max: 50 })
      .withMessage('Custom alias must be 3-50 characters')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Custom alias can only contain letters, numbers, underscores, and hyphens'),
    body('title')
      .optional()
      .isLength({ max: 200 })
      .withMessage('Title too long'),
    body('description')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Description too long'),
    body('expiryDays')
      .optional()
      .isInt({ min: 1, max: 3650 })
      .withMessage('Expiry days must be between 1 and 3650'),
    body('tags')
      .optional()
      .isArray()
      .withMessage('Tags must be an array'),
    body('tags.*')
      .optional()
      .isLength({ max: 50 })
      .withMessage('Each tag must be max 50 characters')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const {
        longUrl,
        customAlias,
        title,
        description,
        expiryDays,
        tags
      } = req.body;

      // Check if custom alias requires premium
      if (customAlias && req.user && !req.user.isPremium) {
        return res.status(403).json({
          success: false,
          error: 'Custom aliases require a premium subscription',
          upgradeUrl: '/upgrade'
        });
      }

      const urlData = {
        longUrl,
        customAlias,
        userId: req.user?._id || null,
        title,
        description,
        expiryDays,
        tags
      };

      const urlMapping = await UrlService.shortenUrl(urlData.longUrl, urlData.userId, urlData.customAlias);

      // Update user usage if authenticated
      if (req.user) {
        await req.user.incrementUsage();
      }

      res.status(201).json({
        success: true,
        data: urlMapping
      });

    } catch (error) {
      logger.error('Error creating short URL:', error);
      
      if (error.message.includes('blocked') || error.message.includes('malicious')) {
        return res.status(400).json({
          success: false,
          error: 'URL blocked',
          message: error.message
        });
      }

      if (error.message.includes('taken')) {
        return res.status(409).json({
          success: false,
          error: 'Custom alias already taken',
          message: error.message
        });
      }

      next(error);
    }
  }
);

/**
 * GET /api/urls/:shortId
 * Get URL information by short ID
 */
router.get('/:shortId',
  authMiddleware.optionalAuth,
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format')
      .isLength({ max: 50 })
      .withMessage('Short ID too long')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;
      
      const urlMapping = await UrlService.getUrlInfo(shortId);
      
      if (!urlMapping) {
        return res.status(404).json({
          success: false,
          error: 'URL not found'
        });
      }

      // Check if user has access to view this URL's details
      const hasAccess = !urlMapping.userId || 
                       (req.user && (req.user._id.toString() === urlMapping.userId.toString() || req.user.role === 'admin'));

      const responseData = {
        shortId: urlMapping.shortId,
        shortUrl: `${process.env.BASE_URL}/${urlMapping.shortId}`,
        longUrl: urlMapping.longUrl,
        clickCount: urlMapping.analytics.clickCount,
        createdAt: urlMapping.createdAt
      };

      // Add additional details if user has access
      if (hasAccess) {
        responseData.title = urlMapping.metadata?.title;
        responseData.description = urlMapping.metadata?.description;
        responseData.uniqueClickCount = urlMapping.analytics.uniqueClickCount;
        responseData.expiresAt = urlMapping.expiresAt;
        responseData.metadata = urlMapping.metadata;
        responseData.userId = urlMapping.userId;
      }

      res.json({
        success: true,
        data: responseData
      });

    } catch (error) {
      logger.error('Error getting URL info:', error);
      next(error);
    }
  }
);

/**
 * PUT /api/urls/:shortId
 * Update URL settings
 */
router.put('/:shortId',
  authMiddleware.authenticate,
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format'),
    body('title')
      .optional()
      .isLength({ max: 200 })
      .withMessage('Title too long'),
    body('description')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Description too long'),
    body('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be boolean'),
    body('expiresAt')
      .optional()
      .isISO8601()
      .withMessage('Invalid expiry date format'),
    body('tags')
      .optional()
      .isArray()
      .withMessage('Tags must be an array')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;
      const updates = req.body;

      const urlMapping = await UrlService.updateUrl(shortId, updates, req.user._id);

      res.json({
        success: true,
        data: urlMapping
      });

    } catch (error) {
      logger.error('Error updating URL:', error);
      
      if (error.message.includes('not found') || error.message.includes('access denied')) {
        return res.status(404).json({
          success: false,
          error: error.message
        });
      }

      next(error);
    }
  }
);

/**
 * DELETE /api/urls/:shortId
 * Delete a URL
 */
router.delete('/:shortId',
  authMiddleware.authenticate,
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;

      await UrlService.deleteUrl(shortId, req.user._id);

      res.json({
        success: true,
        message: 'URL deleted successfully'
      });

    } catch (error) {
      logger.error('Error deleting URL:', error);
      
      if (error.message.includes('not found') || error.message.includes('access denied')) {
        return res.status(404).json({
          success: false,
          error: error.message
        });
      }

      next(error);
    }
  }
);

/**
 * GET /api/urls/:shortId/qr
 * Generate QR code for a URL
 */
router.get('/:shortId/qr',
  authMiddleware.optionalAuth,
  // authMiddleware.requirePremiumFeature('qr_codes'), // Temporarily disabled for testing
  [
    param('shortId')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid short ID format')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;

      const qrCodeDataUrl = await UrlService.generateQRCode(shortId);

      res.json({
        success: true,
        data: {
          qrCode: qrCodeDataUrl,
          shortId,
          format: 'data:image/png;base64'
        }
      });

    } catch (error) {
      logger.error('Error generating QR code:', error);
      next(error);
    }
  }
);

/**
 * GET /api/urls/user/:userId
 * Get user's URLs
 */
router.get('/user/:userId',
  authMiddleware.authenticate,
  authMiddleware.requireOwnershipOrAdmin('userId'),
  [
    param('userId')
      .isMongoId()
      .withMessage('Invalid user ID'),
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
    query('sortBy')
      .optional()
      .isIn(['createdAt', 'clickCount', 'title', 'longUrl'])
      .withMessage('Invalid sort field'),
    query('sortOrder')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('Sort order must be asc or desc'),
    query('activeOnly')
      .optional()
      .isBoolean()
      .withMessage('activeOnly must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { userId } = req.params;
      const options = {
        page: parseInt(req.query.page) || 1,
        limit: parseInt(req.query.limit) || 20,
        search: req.query.search,
        sortBy: req.query.sortBy || 'createdAt',
        sortOrder: req.query.sortOrder || 'desc',
        activeOnly: req.query.activeOnly === 'true'
      };

      const result = await UrlService.getUserUrls(userId, options);

      res.json({
        success: true,
        data: result.urls,
        pagination: result.pagination
      });

    } catch (error) {
      logger.error('Error getting user URLs:', error);
      next(error);
    }
  }
);

/**
 * POST /api/urls/:shortId/analytics
 * Get URL analytics
 */
router.get('/:shortId/analytics',
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
    query('includeRealTime')
      .optional()
      .isBoolean()
      .withMessage('includeRealTime must be boolean'),
    query('includeFraud')
      .optional()
      .isBoolean()
      .withMessage('includeFraud must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { shortId } = req.params;
      
      // Verify user has access to this URL's analytics
      const urlMapping = await UrlService.getUrlInfo(shortId);
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

      const options = {
        startDate: req.query.startDate ? new Date(req.query.startDate) : undefined,
        endDate: req.query.endDate ? new Date(req.query.endDate) : undefined,
        includeRealTime: req.query.includeRealTime === 'true',
        includeFraud: req.query.includeFraud === 'true'
      };

      const analytics = await UrlService.getAnalytics(shortId, options);

      res.json({
        success: true,
        data: analytics
      });

    } catch (error) {
      logger.error('Error getting URL analytics:', error);
      next(error);
    }
  }
);

/**
 * POST /api/urls/bulk
 * Create multiple short URLs at once
 */
router.post('/bulk',
  authMiddleware.authenticate,
  authMiddleware.requireRole('premium', 'admin'),
  rateLimitMiddleware.urlShorteningLimiter,
  [
    body('urls')
      .isArray({ min: 1, max: 100 })
      .withMessage('URLs array must contain 1-100 items'),
    body('urls.*.longUrl')
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Valid URL is required'),
    body('urls.*.customAlias')
      .optional()
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Invalid custom alias format')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { urls } = req.body;
      const results = [];
      const errors = [];

      for (const [index, urlData] of urls.entries()) {
        try {
          const urlMapping = await UrlService.createShortUrl({
            ...urlData,
            userId: req.user._id
          });

          results.push({
            index,
            success: true,
            data: {
              shortId: urlMapping.shortId,
              shortUrl: urlMapping.fullShortUrl,
              longUrl: urlMapping.longUrl
            }
          });

          // Increment user usage
          await req.user.incrementUsage();

        } catch (error) {
          errors.push({
            index,
            success: false,
            error: error.message,
            longUrl: urlData.longUrl
          });
        }
      }

      res.status(201).json({
        success: true,
        data: {
          successful: results.length,
          failed: errors.length,
          results,
          errors
        }
      });

    } catch (error) {
      logger.error('Error in bulk URL creation:', error);
      next(error);
    }
  }
);

module.exports = router; 