const mongoose = require('mongoose');

const ClickEventSchema = new mongoose.Schema({
  shortId: {
    type: String,
    required: true,
    index: true,
    ref: 'URLMapping'
  },
  urlMappingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'URLMapping',
    required: true,
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  },
  ip: {
    type: String,
    required: true,
    index: true
  },
  hashedIp: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    required: true,
    maxlength: 500
  },
  referrer: {
    type: String,
    maxlength: 500,
    default: null
  },
  geoLocation: {
    country: String,
    region: String,
    city: String,
    timezone: String,
    coordinates: {
      lat: Number,
      lon: Number
    }
  },
  device: {
    type: {
      type: String,
      enum: ['mobile', 'tablet', 'desktop', 'bot', 'unknown'],
      default: 'unknown'
    },
    browser: String,
    os: String,
    brand: String,
    model: String
  },
  sessionId: {
    type: String,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true
  },
  isUnique: {
    type: Boolean,
    default: false,
    index: true
  },
  fraudDetection: {
    isBot: {
      type: Boolean,
      default: false
    },
    isSuspicious: {
      type: Boolean,
      default: false
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 1,
      default: 0
    },
    fraudReasons: [{
      type: String,
      enum: [
        'rapid_clicking',
        'suspicious_user_agent',
        'bot_detected',
        'ip_reputation',
        'geographic_anomaly',
        'unusual_referrer',
        'click_pattern_anomaly',
        'vpn_proxy_detected'
      ]
    }],
    aiAnalyzed: {
      type: Boolean,
      default: false
    },
    aiScore: {
      type: Number,
      min: 0,
      max: 1,
      default: null
    }
  },
  performance: {
    loadTime: Number, // milliseconds
    redirectTime: Number, // milliseconds
    dnsTime: Number // milliseconds
  },
  campaign: {
    source: String,
    medium: String,
    campaign: String,
    term: String,
    content: String
  },
  metadata: {
    language: String,
    screenResolution: String,
    colorDepth: Number,
    timezoneOffset: Number,
    plugins: [String]
  }
}, {
  timestamps: false, // We use our own timestamp field
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for analytics queries
ClickEventSchema.index({ shortId: 1, timestamp: -1 });
ClickEventSchema.index({ urlMappingId: 1, timestamp: -1 });
ClickEventSchema.index({ timestamp: -1 });
ClickEventSchema.index({ 'geoLocation.country': 1 });
ClickEventSchema.index({ 'device.type': 1 });
ClickEventSchema.index({ 'fraudDetection.isBot': 1 });
ClickEventSchema.index({ 'fraudDetection.isSuspicious': 1 });
ClickEventSchema.index({ userId: 1, timestamp: -1 });
ClickEventSchema.index({ hashedIp: 1, timestamp: -1 });

// TTL index for data retention (keep clicks for 2 years by default)
ClickEventSchema.index({ timestamp: 1 }, { 
  expireAfterSeconds: 63072000 // 2 years
});

// Virtual for getting the hour of the day
ClickEventSchema.virtual('hour').get(function() {
  return this.timestamp.getHours();
});

// Virtual for getting the day of the week
ClickEventSchema.virtual('dayOfWeek').get(function() {
  return this.timestamp.getDay();
});

// Virtual for getting click age in hours
ClickEventSchema.virtual('ageHours').get(function() {
  return Math.floor((Date.now() - this.timestamp.getTime()) / (1000 * 60 * 60));
});

// Static method to get analytics for a URL
ClickEventSchema.statics.getAnalytics = function(shortId, options = {}) {
  const {
    startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
    endDate = new Date(),
    groupBy = 'day'
  } = options;

  const matchStage = {
    shortId,
    timestamp: { $gte: startDate, $lte: endDate },
    'fraudDetection.isBot': { $ne: true }
  };

  let groupByFormat;
  switch (groupBy) {
    case 'hour':
      groupByFormat = '%Y-%m-%d-%H';
      break;
    case 'day':
      groupByFormat = '%Y-%m-%d';
      break;
    case 'month':
      groupByFormat = '%Y-%m';
      break;
    default:
      groupByFormat = '%Y-%m-%d';
  }

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: groupByFormat, date: '$timestamp' } }
        },
        clicks: { $sum: 1 },
        uniqueClicks: { $sum: { $cond: ['$isUnique', 1, 0] } },
        countries: { $addToSet: '$geoLocation.country' },
        devices: { $addToSet: '$device.type' },
        referrers: { $addToSet: '$referrer' }
      }
    },
    { $sort: { '_id.date': 1 } }
  ]);
};

// Static method to detect click fraud patterns
ClickEventSchema.statics.detectFraudPatterns = function(shortId, timeWindow = 3600000) { // 1 hour
  const cutoffTime = new Date(Date.now() - timeWindow);
  
  return this.aggregate([
    {
      $match: {
        shortId,
        timestamp: { $gte: cutoffTime }
      }
    },
    {
      $group: {
        _id: '$hashedIp',
        clickCount: { $sum: 1 },
        firstClick: { $min: '$timestamp' },
        lastClick: { $max: '$timestamp' },
        userAgents: { $addToSet: '$userAgent' },
        referrers: { $addToSet: '$referrer' }
      }
    },
    {
      $match: {
        $or: [
          { clickCount: { $gte: 10 } }, // More than 10 clicks from same IP
          { userAgents: { $size: 1 }, clickCount: { $gte: 5 } } // Same user agent, multiple clicks
        ]
      }
    }
  ]);
};

// Static method to get top countries
ClickEventSchema.statics.getTopCountries = function(shortId, limit = 10) {
  return this.aggregate([
    {
      $match: {
        shortId,
        'fraudDetection.isBot': { $ne: true },
        'geoLocation.country': { $exists: true, $ne: null }
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
    { $limit: limit }
  ]);
};

// Static method to get device type statistics
ClickEventSchema.statics.getDeviceStats = function(shortId) {
  return this.aggregate([
    {
      $match: {
        shortId,
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
  ]);
};

// Instance method to calculate fraud score
ClickEventSchema.methods.calculateFraudScore = function() {
  let score = 0;
  const reasons = [];

  // Check for bot indicators
  if (this.userAgent && /bot|crawler|spider|scraper/i.test(this.userAgent)) {
    score += 0.3;
    reasons.push('suspicious_user_agent');
  }

  // Check for rapid clicking (this would need to be called with recent click data)
  if (this.fraudDetection.fraudReasons.includes('rapid_clicking')) {
    score += 0.4;
  }

  // Geographic anomaly check would require additional context
  if (this.fraudDetection.fraudReasons.includes('geographic_anomaly')) {
    score += 0.2;
  }

  this.fraudDetection.riskScore = Math.min(score, 1);
  this.fraudDetection.isSuspicious = score > 0.3;
  this.fraudDetection.isBot = score > 0.6;
  
  return this.fraudDetection.riskScore;
};

module.exports = mongoose.model('ClickEvent', ClickEventSchema); 