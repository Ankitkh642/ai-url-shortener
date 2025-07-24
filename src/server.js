require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const expressWinston = require('express-winston');

const databaseConfig = require('./config/database');
const logger = require('./utils/logger');

// Import routes
const urlRoutes = require('./routes/urlRoutes');
const authRoutes = require('./routes/authRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Import middleware
const authMiddleware = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');
const rateLimitMiddleware = require('./middleware/rateLimit');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (important for rate limiting and IP detection)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.FRONTEND_URL || 'http://localhost:3000'] 
    : true,
  credentials: true,
  optionsSuccessStatus: 200
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
  ignoredRoutes: ['/health', '/favicon.ico']
}));

// Global rate limiting
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000) / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url
    });
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP, please try again later.'
    });
  }
});

app.use(globalLimiter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve static files with cache-busting for development
if (process.env.NODE_ENV === 'development') {
  app.use(express.static('public', {
    setHeaders: (res, path) => {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }));
} else {
  app.use(express.static('public'));
}

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/urls', urlRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/admin', authMiddleware.authenticate, authMiddleware.requireRole('admin'), adminRoutes);

// Test route for cache-busting
app.get('/test', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Public stats endpoint (no authentication required)
app.get('/api/stats', async (req, res) => {
  try {
    const URLMapping = require('./models/URLMapping');
    const ClickEvent = require('./models/ClickEvent');
    
    const [totalUrls, totalClicks, uniqueClicks, blockedUrls] = await Promise.all([
      URLMapping.countDocuments(),
      URLMapping.aggregate([
        { $group: { _id: null, total: { $sum: '$clickCount' } } }
      ]),
      URLMapping.aggregate([
        { $group: { _id: null, total: { $sum: '$uniqueClickCount' } } }
      ]),
      URLMapping.countDocuments({ 
        $or: [
          { 'aiAnalysis.isSpam': true },
          { 'aiAnalysis.riskLevel': 'high' }
        ]
      })
    ]);

    res.json({
      success: true,
      data: {
        totalUrls,
        totalClicks: totalClicks[0]?.total || 0,
        uniqueClicks: uniqueClicks[0]?.total || 0,
        blockedUrls
      }
    });
  } catch (error) {
    logger.error('Error fetching public stats', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics'
    });
  }
});

// URL redirection route (must be after API routes to avoid conflicts)
app.get('/:shortId', async (req, res, next) => {
  try {
    const { shortId } = req.params;
    
    // Basic validation
    if (!/^[a-zA-Z0-9_-]+$/.test(shortId) || shortId.length > 20) {
      return res.status(404).json({
        success: false,
        error: 'Invalid short ID format'
      });
    }

    const UrlService = require('./services/UrlService');

    // Get original URL
    const longUrl = await UrlService.getUrl(shortId);
    
    if (!longUrl) {
      return res.status(404).json({
        success: false,
        error: 'URL not found'
      });
    }

    // Extract click tracking data
    const clickData = {
      ip: req.ip,
      userAgent: req.get('User-Agent') || 'Unknown',
      referrer: req.get('Referrer') || null,
      userId: req.user?.id || null,
      performanceData: {
        loadTime: parseInt(req.get('X-Load-Time')) || null,
        redirectTime: parseInt(req.get('X-Redirect-Time')) || null
      },
      metadata: {
        language: req.get('Accept-Language')?.split(',')[0] || null,
        screenResolution: req.get('X-Screen-Resolution') || null
      }
    };

    // Track click asynchronously (non-blocking)
    UrlService.trackClick(shortId, req).catch(error => {
      logger.error('Error tracking click:', error);
    });

    // Redirect to original URL
    res.redirect(301, longUrl);

  } catch (error) {
    logger.error('Error in redirect handler:', error);
    
    if (error.message.includes('expired') || error.message.includes('deactivated') || error.message.includes('malicious')) {
      return res.status(410).json({
        success: false,
        error: 'URL blocked',
        reason: error.message,
        shortId: req.params.shortId
      });
    }
    
    next(error);
  }
});

// Catch-all for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found on this server.',
    path: req.originalUrl
  });
});

// Error logging middleware
app.use(expressWinston.errorLogger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}} - {{res.statusCode}} - {{res.responseTime}}ms"
}));

// Global error handler
app.use(errorHandler);

// Graceful shutdown handler
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}, starting graceful shutdown...`);
  
  // Close server
  if (global.server) {
    global.server.close(() => {
      logger.info('HTTP server closed');
    });
  }

  try {
    // Close database connections
    await databaseConfig.disconnect();
    logger.info('Database connections closed');
    
    // Exit process
    process.exit(0);
  } catch (error) {
    logger.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
}

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Application specific logging, throwing an error, or other logic here
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  gracefulShutdown('uncaughtException');
});

// Start server
async function startServer() {
  try {
    // Connect to databases
    await databaseConfig.connectMongoDB();
    await databaseConfig.connectRedis();

    // Start HTTP server
    const server = app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        port: PORT,
        baseUrl: process.env.BASE_URL || `http://localhost:${PORT}`
      });
    });

    // Store server reference for graceful shutdown
    global.server = server;

    return server;
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the application
if (require.main === module) {
  startServer();
}

module.exports = app; 