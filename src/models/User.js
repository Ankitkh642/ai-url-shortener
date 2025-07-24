const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_]+$/,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 100,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  firstName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  avatar: {
    type: String,
    trim: true,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  role: {
    type: String,
    enum: ['user', 'premium', 'admin'],
    default: 'user',
    index: true
  },
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'premium', 'enterprise'],
      default: 'free'
    },
    startDate: Date,
    endDate: Date,
    isActive: {
      type: Boolean,
      default: true
    }
  },
  limits: {
    dailyUrls: {
      type: Number,
      default: 10
    },
    monthlyUrls: {
      type: Number,
      default: 100
    },
    customAliases: {
      type: Number,
      default: 5
    },
    analytics: {
      type: Boolean,
      default: true
    },
    qrCodes: {
      type: Boolean,
      default: true
    }
  },
  usage: {
    totalUrls: {
      type: Number,
      default: 0
    },
    totalClicks: {
      type: Number,
      default: 0
    },
    thisMonthUrls: {
      type: Number,
      default: 0
    },
    todayUrls: {
      type: Number,
      default: 0
    },
    lastResetDate: {
      type: Date,
      default: Date.now
    }
  },
  preferences: {
    defaultExpiry: {
      type: Number,
      default: 365 // days
    },
    emailNotifications: {
      type: Boolean,
      default: true
    },
    analytics: {
      type: Boolean,
      default: true
    },
    publicProfile: {
      type: Boolean,
      default: false
    }
  },
  apiKey: {
    type: String,
    unique: true,
    sparse: true,
    index: true
  },
  refreshTokens: [{
    token: String,
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 604800 // 7 days
    }
  }],
  lastLogin: Date,
  loginCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.refreshTokens;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Indexes
UserSchema.index({ email: 1, isActive: 1 });
UserSchema.index({ username: 1, isActive: 1 });
UserSchema.index({ 'subscription.plan': 1 });
UserSchema.index({ createdAt: -1 });

// Virtual for full name
UserSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.firstName || this.lastName || this.username;
});

// Virtual for checking if user is premium
UserSchema.virtual('isPremium').get(function() {
  return ['premium', 'enterprise'].includes(this.subscription.plan) && this.subscription.isActive;
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Update usage counters
UserSchema.pre('save', function(next) {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const lastReset = new Date(this.usage.lastResetDate);
  const lastResetDay = new Date(lastReset.getFullYear(), lastReset.getMonth(), lastReset.getDate());
  
  // Reset daily counter if it's a new day
  if (today > lastResetDay) {
    this.usage.todayUrls = 0;
    this.usage.lastResetDate = now;
  }
  
  // Reset monthly counter if it's a new month
  if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) {
    this.usage.thisMonthUrls = 0;
  }
  
  next();
});

// Instance method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Instance method to generate JWT token
UserSchema.methods.generateAuthToken = function() {
  const payload = {
    user: {
      id: this._id,
      username: this.username,
      email: this.email,
      role: this.role
    }
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

// Instance method to generate API key
UserSchema.methods.generateApiKey = function() {
  const crypto = require('crypto');
  this.apiKey = `urlsh_${crypto.randomBytes(32).toString('hex')}`;
  return this.apiKey;
};

// Instance method to check usage limits
UserSchema.methods.canCreateUrl = function() {
  if (this.role === 'admin') return true;
  
  const limits = this.limits;
  const usage = this.usage;
  
  return usage.todayUrls < limits.dailyUrls && usage.thisMonthUrls < limits.monthlyUrls;
};

// Instance method to increment usage
UserSchema.methods.incrementUsage = function() {
  this.usage.totalUrls += 1;
  this.usage.thisMonthUrls += 1;
  this.usage.todayUrls += 1;
  return this.save();
};

// Static method to find by email or username
UserSchema.statics.findByEmailOrUsername = function(identifier) {
  return this.findOne({
    $or: [
      { email: identifier.toLowerCase() },
      { username: identifier }
    ],
    isActive: true
  });
};

module.exports = mongoose.model('User', UserSchema); 