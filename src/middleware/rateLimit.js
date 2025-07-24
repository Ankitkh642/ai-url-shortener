const rateLimit = require('express-rate-limit');
const CacheService = require('../services/CacheService');
const logger = require('../utils/logger');

const cacheService = new CacheService();

/**
 * Create a rate limiter for URL shortening
 */
const urlShorteningLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: async (req) => {
    // Higher limits for authenticated users
    if (req.user) {
      switch (req.user.role) {
        case 'admin':
          return 1000; // Very high limit for admins
        case 'premium':
          return 200; // Higher limit for premium users
        default:
          return 50; // Standard limit for regular users
      }
    }
    return 10; // Lower limit for anonymous users
  },
  message: {
    error: 'Too many URL creation requests',
    message: 'You have exceeded the URL shortening rate limit. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use user ID if authenticated, otherwise IP
    return req.user ? `user:${req.user._id}` : `ip:${req.ip}`;
  },
  handler: (req, res) => {
    logger.warn('URL shortening rate limit exceeded', {
      userId: req.user?._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many URL creation requests. Please try again later.',
      retryAfter: Math.ceil(15 * 60) // 15 minutes in seconds
    });
  }
});

/**
 * Create a rate limiter for authentication endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many authentication attempts',
    message: 'Too many failed login attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  keyGenerator: (req) => {
    // Use email/username if provided, otherwise IP
    const identifier = req.body.email || req.body.username || req.ip;
    return `auth:${identifier}`;
  },
  handler: (req, res) => {
    logger.warn('Authentication rate limit exceeded', {
      identifier: req.body.email || req.body.username,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many authentication attempts',
      message: 'Too many failed login attempts. Please try again in 15 minutes.',
      retryAfter: Math.ceil(15 * 60)
    });
  }
});

/**
 * Create a rate limiter for analytics requests
 */
const analyticsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: async (req) => {
    if (req.user) {
      switch (req.user.role) {
        case 'admin':
          return 500;
        case 'premium':
          return 100;
        default:
          return 30;
      }
    }
    return 10; // Very limited for anonymous users
  },
  message: {
    error: 'Too many analytics requests',
    message: 'You have exceeded the analytics request rate limit.'
  },
  keyGenerator: (req) => {
    return req.user ? `analytics:user:${req.user._id}` : `analytics:ip:${req.ip}`;
  },
  handler: (req, res) => {
    logger.warn('Analytics rate limit exceeded', {
      userId: req.user?._id,
      ip: req.ip
    });
    
    res.status(429).json({
      success: false,
      error: 'Analytics rate limit exceeded',
      message: 'Too many analytics requests. Please try again later.'
    });
  }
});

/**
 * Custom rate limiter using Redis for more sophisticated rate limiting
 */
const customRateLimit = (options = {}) => {
  const {
    windowMs = 60000, // 1 minute
    max = 100,
    keyGenerator = (req) => req.ip,
    message = 'Rate limit exceeded',
    skipSuccessfulRequests = false,
    skipFailedRequests = false
  } = options;

  return async (req, res, next) => {
    try {
      const key = keyGenerator(req);
      const window = Math.floor(Date.now() / windowMs);
      const cacheKey = `${key}:${window}`;

      // Get current count
      const current = await cacheService.getRateLimit(key, window.toString());
      
      // Check if limit exceeded
      if (current >= max) {
        logger.warn('Custom rate limit exceeded', {
          key,
          current,
          max,
          window: windowMs
        });

        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded',
          message,
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      // Increment counter
      await cacheService.incrementRateLimit(key, window.toString(), Math.ceil(windowMs / 1000));

      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': max,
        'X-RateLimit-Remaining': Math.max(0, max - current - 1),
        'X-RateLimit-Reset': new Date(Date.now() + windowMs).toISOString()
      });

      // Skip counting based on response status if configured
      if (skipSuccessfulRequests || skipFailedRequests) {
        const originalSend = res.send;
        res.send = function(data) {
          const statusCode = res.statusCode;
          const shouldSkip = 
            (skipSuccessfulRequests && statusCode < 400) ||
            (skipFailedRequests && statusCode >= 400);

          if (shouldSkip) {
            // Decrement the counter since we're skipping this request
            cacheService.incrementRateLimit(key, window.toString(), Math.ceil(windowMs / 1000), -1)
              .catch(err => logger.error('Error decrementing rate limit:', err));
          }

          return originalSend.call(this, data);
        };
      }

      next();

    } catch (error) {
      logger.error('Custom rate limit error:', error);
      // Continue without rate limiting if Redis is down
      next();
    }
  };
};

/**
 * Rate limiter for password reset requests
 */
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour
  message: {
    error: 'Too many password reset requests',
    message: 'Too many password reset attempts. Please try again in an hour.'
  },
  keyGenerator: (req) => {
    return `pwd_reset:${req.body.email || req.ip}`;
  },
  handler: (req, res) => {
    logger.warn('Password reset rate limit exceeded', {
      email: req.body.email,
      ip: req.ip
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many password reset requests',
      message: 'You have requested too many password resets. Please try again in an hour.'
    });
  }
});

/**
 * Rate limiter for API endpoints
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: async (req) => {
    if (req.user) {
      switch (req.user.role) {
        case 'admin':
          return 10000;
        case 'premium':
          return 1000;
        default:
          return 100;
      }
    }
    return 50;
  },
  keyGenerator: (req) => {
    return req.user ? `api:user:${req.user._id}` : `api:ip:${req.ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'API rate limit exceeded',
      message: 'Too many API requests. Please try again later.'
    });
  }
});

module.exports = {
  urlShorteningLimiter,
  authLimiter,
  analyticsLimiter,
  customRateLimit,
  passwordResetLimiter,
  apiLimiter
}; 