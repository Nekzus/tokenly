# Tokenly 🔐

[![Github Workflow](https://github.com/nekzus/tokenly/actions/workflows/publish.yml/badge.svg?event=push)](https://github.com/Nekzus/tokenly/actions/workflows/publish.yml)
[![npm-version](https://img.shields.io/npm/v/@nekzus/tokenly.svg)](https://www.npmjs.com/package/@nekzus/tokenly)
[![npm-month](https://img.shields.io/npm/dm/@nekzus/tokenly.svg)](https://www.npmjs.com/package/@nekzus/tokenly)
[![npm-total](https://img.shields.io/npm/dt/@nekzus/tokenly.svg?style=flat)](https://www.npmjs.com/package/@nekzus/tokenly)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
<div align="center">

**Advanced JWT Token Management with Device Fingerprinting**

_Enterprise-grade security by default for modern applications_

</div>

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [API Reference](#api-reference)
- [Environment Variables](#environment-variables--secrets)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **Zero Configuration Required**: Works out of the box with secure defaults
- **Device Fingerprinting**: Unique identification of devices to prevent token theft
- **Framework Agnostic**: Use with Express, Fastify, Koa, or any Node.js framework
- **TypeScript First**: Full type safety and excellent IDE support
- **Production Ready**: Built for enterprise applications

## 📦 Installation

```bash
npm install @nekzus/tokenly
```
### Required Dependencies
```bash
npm install cookie-parser
```

> ⚠️ **Important**: `cookie-parser` is required for secure handling of refresh tokens with HttpOnly cookies.

## 🚀 Quick Start

```typescript
import { Tokenly, getClientIP } from '@nekzus/tokenly';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();

// Required middleware for refresh tokens
app.use(cookieParser());

// Initialize Tokenly
const auth = new Tokenly({
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    securityConfig: {
        enableFingerprint: true,
        maxDevices: 5
    }
});

// Generate token with fingerprinting
app.post('/login', (req, res) => {
    const token = auth.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        {
            userAgent: req.headers['user-agent'] || '',
            ip: getClientIP(req.headers)
        }
    );
    res.json({ token });
});
```

## 🔧 Configuration

### Basic Configuration
```typescript
const auth = new Tokenly({
    accessTokenExpiry: '15m',    // 15 minutes
    refreshTokenExpiry: '7d',    // 7 days
    securityConfig: {
        enableFingerprint: true,  // Enable device tracking
        maxDevices: 5            // Max devices per user
    }
});
```

### Advanced Security Configuration
```typescript
const auth = new Tokenly({
    accessTokenExpiry: '5m',     // Shorter token life
    refreshTokenExpiry: '1d',    // Daily refresh required
    securityConfig: {
        enableFingerprint: true,  // Required for device tracking
        enableBlacklist: true,    // Enable token revocation
        maxDevices: 3            // Strict device limit
    }
});
```

## 🛡️ Security Features

### Device Fingerprinting
- **User Agent**: Browser/client identification
- **IP Address**: Client's IP address
- **Cryptographic Salt**: Unique per instance
- **Consistent Hashing**: Same device = Same fingerprint

### Token Management
- **Access Tokens**: Short-lived JWTs for API access
- **Refresh Tokens**: Long-lived tokens for session maintenance
- **Blacklisting**: Optional token revocation support
- **Expiration Control**: Configurable token lifetimes

### Security Events
```typescript
// Invalid Fingerprint Detection
auth.on('invalid_fingerprint', (event) => {
    console.log(`Security Alert: Invalid fingerprint detected`);
    console.log(`User: ${event.userId}`);
    console.log(`IP: ${event.context.ip}`);
});

// Device Limit Reached
auth.on('max_devices_reached', (event) => {
    console.log(`Device limit reached for user: ${event.userId}`);
    console.log(`Current devices: ${event.context.currentDevices}`);
});
```

## 📘 API Reference

### Token Generation
```typescript
const token = auth.generateAccessToken(
    payload: { userId: string; role: string },
    options?: { fingerprint?: string; deviceId?: string },
    context?: { userAgent: string; ip: string }
);
```

### IP Detection Helper
```typescript
import { getClientIP } from '@nekzus/tokenly';

const clientIP = getClientIP(headers, defaultIP);
```

Priority order:
1. `X-Real-IP`: Direct proxy IP
2. `X-Forwarded-For`: First IP in proxy chain
3. Default IP (if provided)
4. Empty string (fallback)

### Type Definitions
```typescript
interface AccessToken {
    raw: string;
    payload: {
        userId: string;
        role: string;
        [key: string]: any;
    };
}

interface InvalidFingerprintEvent {
    type: 'invalid_fingerprint';
    userId: string;
    token: string;
    context: {
        expectedFingerprint: string;
        receivedFingerprint: string;
        ip: string;
        userAgent: string;
        timestamp: string;
    };
}

interface MaxDevicesEvent {
    type: 'max_devices_reached';
    userId: string;
    context: {
        currentDevices: number;
        maxAllowed: number;
        ip: string;
        userAgent: string;
        timestamp: string;
    };
}
```

## 🔑 Environment Variables & Secrets

### Required Variables
```env
# .env
JWT_SECRET_ACCESS=your_secure_access_token_secret
JWT_SECRET_REFRESH=your_secure_refresh_token_secret
```

When environment variables are not provided, Tokenly automatically:
- Generates cryptographically secure random secrets
- Uses SHA-256 for secret generation
- Implements secure entropy sources
- Creates unique secrets per instance

> ⚠️ **Important**: While auto-generated secrets are cryptographically secure, they regenerate on each application restart. This means all previously issued tokens will become invalid. For production environments, always provide permanent secrets through environment variables.

### Secret Generation
```bash
# Generate secure random secrets
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Security Guidelines
- Never commit secrets to version control
- Use different secrets for development and production
- Minimum length of 32 characters recommended
- Rotate secrets periodically in production
- Use secret management services when available

## 🔐 Best Practices

### Token Security
- Use short-lived access tokens (5-15 minutes)
- Implement refresh token rotation
- Enable blacklisting for critical applications

### Refresh Token Security
- Use HttpOnly cookies for refresh tokens
- Configure cookie-parser middleware
- Enable secure and sameSite options in production
- Implement proper CORS configuration when needed

### Device Management
- Enable fingerprinting for sensitive applications
- Set reasonable device limits per user
- Monitor security events

### IP Detection
- Configure proxy headers correctly
- Use `X-Real-IP` for single proxy setups
- Handle `X-Forwarded-For` for proxy chains

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT © [Nekzus](https://github.com/Nekzus)


