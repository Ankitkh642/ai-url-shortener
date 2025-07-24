# AI-Enhanced URL Shortener

A modern, scalable URL shortener with AI-powered spam detection, comprehensive analytics, and fraud prevention. Built with Node.js, MongoDB, Redis, and enhanced with machine learning capabilities.

## 🌟 Features

### Core Features
- **URL Shortening**: Convert long URLs into short, memorable links
- **Custom Aliases**: Create branded short links (Premium feature)
- **QR Code Generation**: Generate QR codes for short URLs
- **Link Expiration**: Set expiry dates for temporary links
- **Bulk Operations**: Create multiple short URLs at once

### AI-Powered Security
- **Spam Detection**: AI models detect malicious and phishing URLs
- **Click Fraud Prevention**: Machine learning algorithms identify suspicious click patterns
- **Real-time Threat Analysis**: URLs are analyzed before shortening
- **Smart Alias Suggestions**: AI-generated memorable aliases

### Advanced Analytics
- **Comprehensive Tracking**: Clicks, geographic data, device information
- **Real-time Analytics**: Live click tracking and statistics
- **Fraud Detection**: Identify and filter bot traffic
- **Export Capabilities**: CSV and JSON export for data analysis
- **Custom Date Ranges**: Flexible analytics time periods

### User Management
- **Multi-tier Subscriptions**: Free, Basic, Premium, Enterprise plans
- **Usage Limits**: Configurable daily and monthly limits
- **API Access**: RESTful API with authentication
- **Admin Dashboard**: System-wide monitoring and management

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │   AI Services   │
│   (Web UI)      │───▶│   (Express.js)  │───▶│   (ML Models)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                       ┌────────┴────────┐
                       │                 │
               ┌───────▼───────┐ ┌───────▼───────┐
               │   MongoDB     │ │     Redis     │
               │  (Database)   │ │   (Cache)     │
               └───────────────┘ └───────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- MongoDB 5.0+
- Redis 6.0+
- npm or yarn

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd url-shortener
```

2. **Install dependencies**
```bash
npm install
```

3. **Environment Configuration**
```bash
cp config.env.example .env
```

Edit `.env` with your configuration:
```env
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/url-shortener
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-super-secret-jwt-key
IP_SALT=your-ip-hashing-salt

# AI Services (optional)
AI_SERVICE_URL=http://localhost:8000
AI_SERVICE_API_KEY=your-ai-service-key
GOOGLE_SAFE_BROWSING_API_KEY=your-google-api-key

# Application
BASE_URL=http://localhost:3000
```

4. **Start the application**
```bash
# Development
npm run dev

# Production
npm start
```

5. **Access the application**
- Web Interface: http://localhost:3000
- API Documentation: http://localhost:3000/api/health

## 🐳 Docker Setup

### Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Manual Docker Build

```bash
# Build the image
docker build -t url-shortener .

# Run with external MongoDB and Redis
docker run -d \
  --name url-shortener \
  -p 3000:3000 \
  -e MONGODB_URI=mongodb://host.docker.internal:27017/url-shortener \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  url-shortener
```

## 📚 API Documentation

### Authentication

The API supports both JWT tokens and API keys:

```bash
# JWT Token
Authorization: Bearer <jwt-token>

# API Key
X-API-Key: <api-key>
```

### Core Endpoints

#### Shorten URL
```http
POST /api/urls/shorten
Content-Type: application/json

{
  "longUrl": "https://example.com/very/long/url",
  "customAlias": "my-link",
  "title": "My Example Link",
  "expiryDays": 30,
  "tags": ["marketing", "campaign"]
}
```

#### Get URL Info
```http
GET /api/urls/{shortId}
```

#### Get Analytics
```http
GET /api/urls/{shortId}/analytics?startDate=2024-01-01&endDate=2024-01-31
```

#### Generate QR Code
```http
GET /api/urls/{shortId}/qr
```

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePassword123",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "identifier": "john@example.com",
  "password": "SecurePassword123"
}
```

### Analytics Endpoints

#### User Dashboard
```http
GET /api/analytics/dashboard?period=month&includeRealTime=true
```

#### Export Data
```http
GET /api/analytics/export?format=csv&startDate=2024-01-01
```

### Admin Endpoints

#### System Dashboard
```http
GET /api/admin/dashboard
Authorization: Bearer <admin-token>
```

#### Manage Users
```http
GET /api/admin/users?page=1&limit=20&search=john
PUT /api/admin/users/{userId}
```

## 🤖 AI Features Setup

### Google Safe Browsing API
1. Get API key from [Google Cloud Console](https://console.cloud.google.com/)
2. Enable Safe Browsing API
3. Add key to environment variables

### Custom AI Service
The application can integrate with custom ML models for enhanced URL analysis:

```python
# Example Python AI service
from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)
model = joblib.load('url_classifier_model.pkl')

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data['url']
    
    # Your ML logic here
    risk_score = model.predict_proba([url])[0][1]
    
    return jsonify({
        'riskScore': float(risk_score),
        'category': 'safe' if risk_score < 0.5 else 'suspicious',
        'confidence': 0.95
    })
```

## 📊 Analytics & Monitoring

### Key Metrics Tracked
- Click counts (total and unique)
- Geographic distribution
- Device and browser information
- Referrer sources
- Click timestamps
- Fraud detection scores

### Real-time Monitoring
- System health endpoints
- Cache performance metrics
- Database connection status
- AI service availability

### Fraud Detection
- IP-based pattern analysis
- User agent fingerprinting
- Click velocity monitoring
- Geographic anomaly detection

## 🔧 Configuration

### User Limits
Configure per-plan limits in the User model:

```javascript
limits: {
  dailyUrls: 10,     // URLs per day
  monthlyUrls: 100,  // URLs per month
  customAliases: 5,  // Custom aliases allowed
  analytics: true,   // Access to analytics
  qrCodes: true     // QR code generation
}
```

### Cache Settings
Redis caching can be configured for optimal performance:

```javascript
// Cache TTL settings
URL_MAPPING_TTL=3600      // 1 hour
ANALYTICS_TTL=300         // 5 minutes
SESSION_TTL=86400         // 24 hours
```

### Rate Limiting
Customize rate limits per endpoint:

```javascript
// Rate limit configurations
RATE_LIMIT_WINDOW_MS=900000    // 15 minutes
RATE_LIMIT_MAX_REQUESTS=100    // Max requests per window
```

## 🚀 Deployment

### Production Considerations

1. **Environment Variables**
   - Use strong JWT secrets
   - Configure proper database URLs
   - Set up monitoring credentials

2. **Database Optimization**
   - Enable MongoDB indexing
   - Configure Redis persistence
   - Set up database backups

3. **Security**
   - Enable HTTPS
   - Configure CORS properly
   - Use rate limiting
   - Enable request logging

4. **Monitoring**
   - Set up log aggregation
   - Configure health checks
   - Monitor performance metrics

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: url-shortener
spec:
  replicas: 3
  selector:
    matchLabels:
      app: url-shortener
  template:
    metadata:
      labels:
        app: url-shortener
    spec:
      containers:
      - name: url-shortener
        image: url-shortener:latest
        ports:
        - containerPort: 3000
        env:
        - name: MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: mongodb-uri
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow ESLint configuration
- Write unit tests for new features
- Update documentation
- Ensure backward compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

**MongoDB Connection Issues**
```bash
# Check MongoDB status
sudo systemctl status mongod

# Restart MongoDB
sudo systemctl restart mongod
```

**Redis Connection Issues**
```bash
# Check Redis status
redis-cli ping

# Should return: PONG
```

**Port Already in Use**
```bash
# Find process using port 3000
lsof -i :3000

# Kill the process
kill -9 <PID>
```

### Getting Help
- Create an issue for bugs
- Join our Discord for community support
- Check the documentation wiki
- Review existing issues and discussions

## 🎯 Roadmap

- [ ] Browser extensions
- [ ] Mobile applications
- [ ] Advanced A/B testing
- [ ] Webhook integrations
- [ ] Advanced ML models
- [ ] Multi-language support
- [ ] CDN integration
- [ ] Real-time collaboration

---

Built with ❤️ using Node.js, MongoDB, Redis, and AI 