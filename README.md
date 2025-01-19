# Tokenly

A secure and feature-rich JWT token manager with HttpOnly cookie support for modern web applications.

[![npm version](https://badge.fury.io/js/@nekzus%2Ftokenly.svg)](https://badge.fury.io/js/@nekzus%2Ftokenly)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Security Rating](https://img.shields.io/badge/Security-A%2B-brightgreen.svg)](https://github.com/Nekzus/tokenly/security)

## 🌟 Features

- 🔐 **Advanced Security**
  - JWT token management with HS512 encryption
  - Secure HttpOnly cookie support
  - CSRF protection
  - XSS prevention measures
  
- 🔄 **Token Management**
  - Automatic token rotation
  - Token blacklisting
  - Token revocation
  - Expiration handling
  
- 👆 **Device Security**
  - Device fingerprinting
  - Multi-device management
  - Device limit enforcement
  - Suspicious activity detection
  
- ⚡ **Performance & Reliability**
  - Token caching
  - Automatic cleanup
  - Memory optimization
  - Error resilience
  
- 🛠️ **Developer Experience**
  - Full TypeScript support
  - Comprehensive logging
  - Event system
  - Detailed error messages

## 📦 Installation

```bash
# Using npm
npm install @nekzus/tokenly

# Using yarn
yarn add @nekzus/tokenly

# Using pnpm
pnpm add @nekzus/tokenly
```

## 🚀 Quick Start

### Basic Usage

```typescript
import { Tokenly } from '@nekzus/tokenly';

// Initialize with basic configuration
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d'
});

// Generate tokens
const accessToken = tokenly.generateAccessToken({
  userId: '123',
  role: 'user'
});

// Verify tokens
const verified = tokenly.verifyAccessToken(accessToken.raw);
```

### Advanced Usage

```typescript
// Initialize with advanced security features
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    domain: 'yourdomain.com'
  },
  jwtOptions: {
    algorithm: 'HS512',
    issuer: 'your-app',
    audience: 'your-api'
  },
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 5,
    revokeOnSecurityBreach: true
  },
  rotationConfig: {
    enableAutoRotation: true,
    rotationInterval: 60,
    maxRotationCount: 100,
    rotateBeforeExpiry: 300
  }
});

// Generate token with device fingerprint
const token = await tokenly.generateAccessToken(
  { userId: '123', role: 'user' },
  { 
    userAgent: navigator.userAgent,
    ip: clientIP,
    additionalData: deviceInfo
  }
);

// Enable security features
tokenly.enableAutoRotation();
tokenly.enableAutoCleanup();
tokenly.enableSecurityMonitoring();
```

## 🔧 Configuration

### Environment Variables

```env
# Required
JWT_SECRET_ACCESS=your-secure-access-token-secret
JWT_SECRET_REFRESH=your-secure-refresh-token-secret

# Optional
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
TOKEN_ISSUER=your-app-name
TOKEN_AUDIENCE=your-api
COOKIE_DOMAIN=yourdomain.com
MAX_DEVICES=5
ROTATION_INTERVAL=60
SECURITY_LEVEL=high
```

### Security Levels

```typescript
// High security configuration
const tokenly = new Tokenly({
  securityLevel: 'high',
  // This automatically sets:
  // - HS512 algorithm
  // - Strict cookie settings
  // - Fingerprint validation
  // - Short token expiry
  // - Automatic rotation
});

// Custom security configuration
const tokenly = new Tokenly({
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 5,
    revokeOnSecurityBreach: true,
    validateIP: true,
    validateUserAgent: true,
    preventReuse: true
  }
});
```

## 🛡️ Security Features

### Token Security Analysis

```typescript
const analysis = tokenly.analyzeTokenSecurity(token);
// Returns detailed security analysis:
{
  algorithm: 'HS512',
  hasFingerprint: true,
  expirationTime: Date,
  issuedAt: Date,
  timeUntilExpiry: 840000,
  strength: 'strong',
  vulnerabilities: [],
  recommendations: []
}
```

### Device Management

```typescript
// Get active devices
const devices = tokenly.getActiveDevices(userId);

// Revoke specific device
tokenly.revokeDevice(userId, deviceId);

// Clear all devices except current
tokenly.clearOtherDevices(userId, currentDeviceId);
```

### Event Handling

```typescript
// Security events
tokenly.on('securityBreach', (data) => {
  console.log('Security breach detected:', data);
});

tokenly.on('suspiciousActivity', (data) => {
  console.log('Suspicious activity:', data);
});

// Token lifecycle events
tokenly.on('tokenCreated', (data) => {
  console.log('New token created:', data);
});

tokenly.on('tokenExpiring', (data) => {
  console.log('Token about to expire:', data);
});

tokenly.on('tokenRevoked', (data) => {
  console.log('Token revoked:', data);
});

// Device events
tokenly.on('deviceAdded', (data) => {
  console.log('New device added:', data);
});

tokenly.on('maxDevicesReached', (data) => {
  console.log('Max devices reached:', data);
});
```

## 📊 Response Types

### TokenlyResponse

```typescript
interface TokenlyResponse {
  raw: string;           // Raw JWT token
  payload: {             // Decoded payload
    userId: string;
    role: string;
    [key: string]: any;
    iat?: Date;         // Issued at
    exp?: Date;         // Expires at
  };
  metadata: {           // Token metadata
    fingerprint?: string;
    deviceId?: string;
    issuer?: string;
    audience?: string;
  };
  cookieConfig?: {      // Cookie configuration
    name: string;
    value: string;
    options: TokenlyOptions;
  };
  security: {          // Security information
    strength: 'weak' | 'medium' | 'strong';
    warnings: string[];
    recommendations: string[];
  };
}
```

## 🔍 Error Handling

```typescript
try {
  const token = tokenly.generateAccessToken(payload);
} catch (error) {
  if (error instanceof TokenlyError) {
    switch (error.code) {
      case 'INVALID_PAYLOAD':
        console.error('Invalid payload provided');
        break;
      case 'SECURITY_BREACH':
        console.error('Security breach detected');
        break;
      case 'MAX_DEVICES_REACHED':
        console.error('Maximum devices reached');
        break;
      default:
        console.error('Unknown error:', error.message);
    }
  }
}
```

## 📚 Best Practices

### Security Recommendations

1. **Token Management**
   - Use short-lived access tokens (15-30 minutes)
   - Implement refresh token rotation
   - Enable fingerprint validation
   - Use secure cookie settings

2. **Environment Setup**
   - Use strong secrets
   - Set appropriate CORS policies
   - Enable HTTPS only
   - Configure secure headers

3. **Monitoring & Maintenance**
   - Monitor security events
   - Implement rate limiting
   - Regular security audits
   - Keep dependencies updated

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- 📧 Email: support@tokenly.dev
- 💻 GitHub Issues: [Create an issue](https://github.com/Nekzus/tokenly/issues)
- 📚 Documentation: [Full documentation](https://tokenly.dev/docs)

## 👨‍💻 Author

- **Nekzus** - [GitHub Profile](https://github.com/Nekzus)

## 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by best practices in JWT security
- Built with modern web security in mind

