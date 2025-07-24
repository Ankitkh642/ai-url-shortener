const mongoose = require('mongoose');

const URLMappingSchema = new mongoose.Schema({
  shortId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    trim: true,
    maxlength: 20
  },
  longUrl: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2048,
    validate: {
      validator: function(v) {
        try {
          new URL(v);
          return true;
        } catch {
          return false;
        }
      },
      message: 'Invalid URL format'
    }
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true
  },
  customAlias: {
    type: String,
    trim: true,
    maxlength: 50,
    default: null
  },
  title: {
    type: String,
    trim: true,
    maxlength: 200,
    default: null
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500,
    default: null
  },
  clickCount: {
    type: Number,
    default: 0,
    min: 0
  },
  uniqueClickCount: {
    type: Number,
    default: 0,
    min: 0
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  expiresAt: {
    type: Date,
    default: null
  },
  meta: {
    lastAccessed: {
      type: Date,
      default: null
    },
    aiSpamScore: {
      type: Number,
      min: 0,
      max: 1,
      default: 0
    },
    aiSpamVerdict: {
      type: String,
      enum: ['safe', 'suspicious', 'malicious', 'pending'],
      default: 'pending'
    },
    tags: [{
      type: String,
      trim: true,
      maxlength: 50
    }],
    category: {
      type: String,
      trim: true,
      maxlength: 50,
      default: null
    },
    qrCodeGenerated: {
      type: Boolean,
      default: false
    },
    passwordProtected: {
      type: Boolean,
      default: false
    },
    password: {
      type: String,
      default: null
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better performance
URLMappingSchema.index({ userId: 1, createdAt: -1 });
URLMappingSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
URLMappingSchema.index({ 'meta.aiSpamVerdict': 1 });
URLMappingSchema.index({ clickCount: -1 });

// Virtual for checking if URL is expired
URLMappingSchema.virtual('isExpired').get(function() {
  if (!this.expiresAt) return false;
  return new Date() > this.expiresAt;
});

// Virtual for getting the full short URL
URLMappingSchema.virtual('fullShortUrl').get(function() {
  return `${process.env.BASE_URL}/${this.shortId}`;
});

// Pre-save middleware to update lastAccessed when clickCount changes
URLMappingSchema.pre('save', function(next) {
  if (this.isModified('clickCount')) {
    this.meta.lastAccessed = new Date();
  }
  next();
});

// Method to increment click count
URLMappingSchema.methods.incrementClickCount = function(isUnique = false) {
  this.clickCount += 1;
  if (isUnique) {
    this.uniqueClickCount += 1;
  }
  this.meta.lastAccessed = new Date();
  return this.save();
};

// Method to check if URL is accessible
URLMappingSchema.methods.isAccessible = function() {
  if (!this.isActive) return false;
  if (this.isExpired) return false;
  if (this.meta.aiSpamVerdict === 'malicious') return false;
  return true;
};

// Static method to find active URLs
URLMappingSchema.statics.findActive = function() {
  return this.find({
    isActive: true,
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ]
  });
};

// Static method to find URLs by user
URLMappingSchema.statics.findByUser = function(userId, options = {}) {
  const query = { userId };
  
  if (options.activeOnly) {
    query.isActive = true;
    if (options.includeExpired !== true) {
      query.$or = [
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } }
      ];
    }
  }

  return this.find(query)
    .sort(options.sort || { createdAt: -1 })
    .limit(options.limit || 0);
};

module.exports = mongoose.model('URLMapping', URLMappingSchema); 