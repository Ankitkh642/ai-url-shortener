const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * Middleware to authenticate JWT tokens
 */
const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Get token from API key header
    else if (req.headers['x-api-key']) {
      const apiKey = req.headers['x-api-key'];
      const user = await User.findOne({ apiKey, isActive: true });
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key'
        });
      }

      req.user = user;
      req.authType = 'api_key';
      return next();
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. No token provided.'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from token
      const user = await User.findById(decoded.user.id).select('-password');
      
      if (!user || !user.isActive) {
        return res.status(401).json({
          success: false,
          error: 'Token is not valid or user is inactive'
        });
      }

      req.user = user;
      req.authType = 'jwt';
      next();

    } catch (error) {
      logger.error('JWT verification error:', error);
      
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          error: 'Token expired'
        });
      }
      
      return res.status(401).json({
        success: false,
        error: 'Token is not valid'
      });
    }

  } catch (error) {
    logger.error('Authentication middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Server Error'
    });
  }
};

/**
 * Middleware for optional authentication
 * Sets req.user if valid token is provided, but doesn't fail if no token
 */
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Get token from API key header
    else if (req.headers['x-api-key']) {
      const apiKey = req.headers['x-api-key'];
      const user = await User.findOne({ apiKey, isActive: true });
      
      if (user) {
        req.user = user;
        req.authType = 'api_key';
      }
      
      return next();
    }

    // If no token, continue without authentication
    if (!token) {
      return next();
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from token
      const user = await User.findById(decoded.user.id).select('-password');
      
      if (user && user.isActive) {
        req.user = user;
        req.authType = 'jwt';
      }

    } catch (error) {
      // Log but don't fail - this is optional auth
      logger.debug('Optional auth token verification failed:', error.message);
    }

    next();

  } catch (error) {
    logger.error('Optional authentication middleware error:', error);
    // Don't fail on optional auth errors
    next();
  }
};

/**
 * Middleware to require specific roles
 * @param {...string} roles - Required roles
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. Authentication required.'
      });
    }

    if (!roles.includes(req.user.role)) {
      logger.warn(`Access denied for user ${req.user.id} with role ${req.user.role}`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: roles,
        endpoint: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        error: 'Access denied. Insufficient permissions.'
      });
    }

    next();
  };
};

/**
 * Middleware to check if user owns the resource or is admin
 * @param {string} paramName - Parameter name containing the user ID
 */
const requireOwnershipOrAdmin = (paramName = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. Authentication required.'
      });
    }

    const resourceUserId = req.params[paramName];
    const isOwner = req.user._id.toString() === resourceUserId;
    const isAdmin = req.user.role === 'admin';

    if (!isOwner && !isAdmin) {
      logger.warn(`Access denied for user ${req.user.id} accessing resource owned by ${resourceUserId}`, {
        userId: req.user.id,
        resourceUserId,
        endpoint: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        error: 'Access denied. You can only access your own resources.'
      });
    }

    next();
  };
};

/**
 * Middleware to check usage limits
 */
const checkUsageLimits = async (req, res, next) => {
  try {
    if (!req.user) {
      return next(); // Skip if no user (anonymous usage)
    }

    // Refresh user data to get latest usage
    const user = await User.findById(req.user._id);
    
    if (!user.canCreateUrl()) {
      return res.status(429).json({
        success: false,
        error: 'Usage limit exceeded',
        message: 'You have reached your daily or monthly URL creation limit. Please upgrade your plan or try again later.',
        limits: {
          daily: user.limits.dailyUrls,
          monthly: user.limits.monthlyUrls,
          current: {
            today: user.usage.todayUrls,
            thisMonth: user.usage.thisMonthUrls
          }
        }
      });
    }

    // Update req.user with fresh data
    req.user = user;
    next();

  } catch (error) {
    logger.error('Usage limits check error:', error);
    res.status(500).json({
      success: false,
      error: 'Error checking usage limits'
    });
  }
};

/**
 * Middleware to validate premium features
 * @param {string} feature - Premium feature name
 */
const requirePremiumFeature = (feature) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. Authentication required.'
      });
    }

    if (!req.user.isPremium) {
      return res.status(403).json({
        success: false,
        error: `Premium feature '${feature}' requires an active premium subscription`,
        feature,
        upgradeUrl: '/upgrade'
      });
    }

    // Check specific feature limits
    switch (feature) {
      case 'custom_aliases':
        if (!req.user.limits.customAliases) {
          return res.status(403).json({
            success: false,
            error: 'Custom aliases not available in your plan'
          });
        }
        break;
      
      case 'analytics':
        if (!req.user.limits.analytics) {
          return res.status(403).json({
            success: false,
            error: 'Advanced analytics not available in your plan'
          });
        }
        break;
      
      case 'qr_codes':
        if (!req.user.limits.qrCodes) {
          return res.status(403).json({
            success: false,
            error: 'QR code generation not available in your plan'
          });
        }
        break;
    }

    next();
  };
};

module.exports = {
  authenticate,
  optionalAuth,
  requireRole,
  requireOwnershipOrAdmin,
  checkUsageLimits,
  requirePremiumFeature
}; 