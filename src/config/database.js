const mongoose = require('mongoose');
const redis = require('redis');
const logger = require('../utils/logger');

class DatabaseConfig {
  constructor() {
    this.mongoConnection = null;
    this.redisClient = null;
  }

  async connectMongoDB() {
    try {
      this.mongoConnection = await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });

      logger.info('MongoDB connected successfully');
      
      mongoose.connection.on('error', (error) => {
        logger.error('MongoDB connection error:', error);
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
      });

      return this.mongoConnection;
    } catch (error) {
      logger.error('MongoDB connection failed:', error);
      process.exit(1);
    }
  }

  async connectRedis() {
    try {
      this.redisClient = redis.createClient({
        url: process.env.REDIS_URL,
        retry_strategy: (options) => {
          if (options.error && options.error.code === 'ECONNREFUSED') {
            logger.error('Redis server connection refused');
            return new Error('Redis connection refused');
          }
          if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Redis retry time exhausted');
          }
          if (options.attempt > 10) {
            return undefined;
          }
          return Math.min(options.attempt * 100, 3000);
        }
      });

      await this.redisClient.connect();
      logger.info('Redis connected successfully');

      this.redisClient.on('error', (error) => {
        logger.error('Redis connection error:', error);
      });

      this.redisClient.on('reconnecting', () => {
        logger.info('Redis reconnecting...');
      });

      return this.redisClient;
    } catch (error) {
      logger.error('Redis connection failed:', error);
      // Redis is optional, continue without it
      return null;
    }
  }

  async disconnect() {
    if (this.mongoConnection) {
      await mongoose.disconnect();
      logger.info('MongoDB disconnected');
    }
    
    if (this.redisClient) {
      await this.redisClient.quit();
      logger.info('Redis disconnected');
    }
  }

  getRedisClient() {
    return this.redisClient;
  }

  getMongoConnection() {
    return this.mongoConnection;
  }
}

module.exports = new DatabaseConfig(); 