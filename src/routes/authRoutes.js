const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const rateLimitMiddleware = require('../middleware/rateLimit');
const logger = require('../utils/logger');

const router = express.Router();

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
 * POST /api/auth/register
 * Register a new user
 */
router.post('/register',
  rateLimitMiddleware.authLimiter,
  [
    body('username')
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be 3-30 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores'),
    body('email')
      .isEmail()
      .withMessage('Valid email is required')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must contain at least one lowercase, one uppercase, and one number'),
    body('firstName')
      .optional()
      .isLength({ max: 50 })
      .withMessage('First name too long'),
    body('lastName')
      .optional()
      .isLength({ max: 50 })
      .withMessage('Last name too long')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { username, email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [
          { email: email.toLowerCase() },
          { username }
        ]
      });

      if (existingUser) {
        const field = existingUser.email === email.toLowerCase() ? 'email' : 'username';
        return res.status(409).json({
          success: false,
          error: `User with this ${field} already exists`
        });
      }

      // Create new user
      const user = new User({
        username,
        email: email.toLowerCase(),
        password,
        firstName,
        lastName
      });

      await user.save();

      // Generate token
      const token = user.generateAuthToken();

      logger.info(`New user registered: ${user.username}`, {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            subscription: user.subscription,
            limits: user.limits
          },
          token
        }
      });

    } catch (error) {
      logger.error('Registration error:', error);
      next(error);
    }
  }
);

/**
 * POST /api/auth/login
 * User login
 */
router.post('/login',
  rateLimitMiddleware.authLimiter,
  [
    body('identifier')
      .notEmpty()
      .withMessage('Email or username is required'),
    body('password')
      .notEmpty()
      .withMessage('Password is required')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { identifier, password } = req.body;

      // Find user by email or username
      const user = await User.findByEmailOrUsername(identifier);

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      // Check password
      const isMatch = await user.comparePassword(password);

      if (!isMatch) {
        logger.warn(`Failed login attempt for user: ${identifier}`, {
          identifier,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      // Update last login
      user.lastLogin = new Date();
      user.loginCount += 1;
      await user.save();

      // Generate token
      const token = user.generateAuthToken();

      logger.info(`User logged in: ${user.username}`, {
        userId: user._id,
        ip: req.ip
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            subscription: user.subscription,
            limits: user.limits,
            usage: user.usage
          },
          token
        }
      });

    } catch (error) {
      logger.error('Login error:', error);
      next(error);
    }
  }
);

/**
 * GET /api/auth/me
 * Get current user profile
 */
router.get('/me',
  authMiddleware.authenticate,
  async (req, res, next) => {
    try {
      // Get fresh user data
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      res.json({
        success: true,
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            avatar: user.avatar,
            role: user.role,
            subscription: user.subscription,
            limits: user.limits,
            usage: user.usage,
            preferences: user.preferences,
            isVerified: user.isVerified,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
          }
        }
      });

    } catch (error) {
      logger.error('Get profile error:', error);
      next(error);
    }
  }
);

/**
 * PUT /api/auth/profile
 * Update user profile
 */
router.put('/profile',
  authMiddleware.authenticate,
  [
    body('firstName')
      .optional()
      .isLength({ max: 50 })
      .withMessage('First name too long'),
    body('lastName')
      .optional()
      .isLength({ max: 50 })
      .withMessage('Last name too long'),
    body('avatar')
      .optional()
      .isURL()
      .withMessage('Avatar must be a valid URL'),
    body('preferences.defaultExpiry')
      .optional()
      .isInt({ min: 1, max: 3650 })
      .withMessage('Default expiry must be between 1 and 3650 days'),
    body('preferences.emailNotifications')
      .optional()
      .isBoolean()
      .withMessage('Email notifications must be boolean'),
    body('preferences.analytics')
      .optional()
      .isBoolean()
      .withMessage('Analytics preference must be boolean'),
    body('preferences.publicProfile')
      .optional()
      .isBoolean()
      .withMessage('Public profile must be boolean')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const updates = req.body;
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Update allowed fields
      const allowedUpdates = ['firstName', 'lastName', 'avatar'];
      allowedUpdates.forEach(field => {
        if (updates[field] !== undefined) {
          user[field] = updates[field];
        }
      });

      // Update preferences
      if (updates.preferences) {
        Object.assign(user.preferences, updates.preferences);
      }

      await user.save();

      logger.info(`User profile updated: ${user.username}`, {
        userId: user._id,
        updates: Object.keys(updates)
      });

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            avatar: user.avatar,
            preferences: user.preferences
          }
        }
      });

    } catch (error) {
      logger.error('Profile update error:', error);
      next(error);
    }
  }
);

/**
 * PUT /api/auth/password
 * Change password
 */
router.put('/password',
  authMiddleware.authenticate,
  [
    body('currentPassword')
      .notEmpty()
      .withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 6 })
      .withMessage('New password must be at least 6 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('New password must contain at least one lowercase, one uppercase, and one number')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Verify current password
      const isMatch = await user.comparePassword(currentPassword);

      if (!isMatch) {
        return res.status(400).json({
          success: false,
          error: 'Current password is incorrect'
        });
      }

      // Update password
      user.password = newPassword;
      await user.save();

      logger.info(`Password changed for user: ${user.username}`, {
        userId: user._id,
        ip: req.ip
      });

      res.json({
        success: true,
        message: 'Password changed successfully'
      });

    } catch (error) {
      logger.error('Password change error:', error);
      next(error);
    }
  }
);

/**
 * POST /api/auth/forgot-password
 * Request password reset
 */
router.post('/forgot-password',
  rateLimitMiddleware.passwordResetLimiter,
  [
    body('email')
      .isEmail()
      .withMessage('Valid email is required')
      .normalizeEmail()
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email: email.toLowerCase(), isActive: true });

      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });

      if (!user) {
        logger.warn(`Password reset requested for non-existent email: ${email}`, {
          email,
          ip: req.ip
        });
        return;
      }

      // TODO: Implement password reset email functionality
      // This would typically involve:
      // 1. Generate a secure reset token
      // 2. Store token with expiration in database
      // 3. Send email with reset link
      // 4. Provide endpoint to verify token and reset password

      logger.info(`Password reset requested for user: ${user.username}`, {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

    } catch (error) {
      logger.error('Forgot password error:', error);
      // Still return success to prevent information leakage
      res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
    }
  }
);

/**
 * POST /api/auth/api-key
 * Generate new API key
 */
router.post('/api-key',
  authMiddleware.authenticate,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Generate new API key
      const apiKey = user.generateApiKey();
      await user.save();

      logger.info(`API key generated for user: ${user.username}`, {
        userId: user._id
      });

      res.json({
        success: true,
        message: 'API key generated successfully',
        data: {
          apiKey
        }
      });

    } catch (error) {
      logger.error('API key generation error:', error);
      next(error);
    }
  }
);

/**
 * DELETE /api/auth/api-key
 * Revoke API key
 */
router.delete('/api-key',
  authMiddleware.authenticate,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Remove API key
      user.apiKey = undefined;
      await user.save();

      logger.info(`API key revoked for user: ${user.username}`, {
        userId: user._id
      });

      res.json({
        success: true,
        message: 'API key revoked successfully'
      });

    } catch (error) {
      logger.error('API key revocation error:', error);
      next(error);
    }
  }
);

/**
 * GET /api/auth/stats
 * Get user statistics
 */
router.get('/stats',
  authMiddleware.authenticate,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Get URL count
      const URLMapping = require('../models/URLMapping');
      const [totalUrls, activeUrls, totalClicks] = await Promise.all([
        URLMapping.countDocuments({ userId: user._id }),
        URLMapping.countDocuments({ 
          userId: user._id, 
          isActive: true,
          $or: [
            { expiresAt: null },
            { expiresAt: { $gt: new Date() } }
          ]
        }),
        URLMapping.aggregate([
          { $match: { userId: user._id } },
          { $group: { _id: null, total: { $sum: '$clickCount' } } }
        ])
      ]);

      const stats = {
        urls: {
          total: totalUrls,
          active: activeUrls,
          inactive: totalUrls - activeUrls
        },
        clicks: {
          total: totalClicks[0]?.total || 0
        },
        usage: user.usage,
        limits: user.limits,
        subscription: user.subscription,
        joinDate: user.createdAt,
        lastLogin: user.lastLogin
      };

      res.json({
        success: true,
        data: stats
      });

    } catch (error) {
      logger.error('Get user stats error:', error);
      next(error);
    }
  }
);

/**
 * DELETE /api/auth/account
 * Delete user account
 */
router.delete('/account',
  authMiddleware.authenticate,
  [
    body('password')
      .notEmpty()
      .withMessage('Password is required to delete account'),
    body('confirmDelete')
      .equals('DELETE')
      .withMessage('Please type DELETE to confirm account deletion')
  ],
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { password } = req.body;
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Verify password
      const isMatch = await user.comparePassword(password);

      if (!isMatch) {
        return res.status(400).json({
          success: false,
          error: 'Incorrect password'
        });
      }

      // Deactivate user instead of hard delete
      user.isActive = false;
      user.email = `deleted_${Date.now()}@deleted.com`;
      await user.save();

      // Deactivate all user's URLs
      const URLMapping = require('../models/URLMapping');
      await URLMapping.updateMany(
        { userId: user._id },
        { isActive: false }
      );

      logger.info(`User account deleted: ${user.username}`, {
        userId: user._id,
        ip: req.ip
      });

      res.json({
        success: true,
        message: 'Account deleted successfully'
      });

    } catch (error) {
      logger.error('Account deletion error:', error);
      next(error);
    }
  }
);

module.exports = router; 