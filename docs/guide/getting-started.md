# Getting Started

## Overview

Tokenly is a JWT token management library that provides enterprise-grade security with minimal configuration.

## Installation

```bash
# npm
npm install @nekzus/tokenly

# yarn
yarn add @nekzus/tokenly

# pnpm
pnpm add @nekzus/tokenly
```

## Quick Start

### Basic Setup

```typescript
import { Tokenly } from '@nekzus/tokenly';

const tokenly = new Tokenly({
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d'
});
```

### Express Integration

```typescript
import express from 'express';
import { Tokenly, getClientIP } from '@nekzus/tokenly';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser());

const tokenly = new Tokenly({
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 5,
        revokeOnSecurityBreach: true
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await authenticate(username, password);

        const accessToken = tokenly.generateAccessToken(
            { userId: user.id },
            undefined,
            {
                userAgent: req.headers['user-agent'],
                ip: getClientIP(req.headers)
            }
        );

        const refreshToken = tokenly.generateRefreshToken({ userId: user.id });

        if (refreshToken.cookieConfig) {
            res.cookie(
                refreshToken.cookieConfig.name,
                refreshToken.cookieConfig.value,
                refreshToken.cookieConfig.options
            );
        }

        res.json({ token: accessToken.raw });
    } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// Token refresh endpoint
app.post('/refresh', async (req, res) => {
    try {
        const oldRefreshToken = req.cookies.refresh_token;
        const tokens = tokenly.rotateTokens(oldRefreshToken);

        if (tokens.refreshToken.cookieConfig) {
            res.cookie(
                tokens.refreshToken.cookieConfig.name,
                tokens.refreshToken.cookieConfig.value,
                tokens.refreshToken.cookieConfig.options
            );
        }

        res.json({ token: tokens.accessToken.raw });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected data' });
});
```

### Authentication Middleware

```typescript
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = tokenly.verifyAccessToken(token);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
}
```

## Security Features

### Device Fingerprinting

```typescript
const tokenly = new Tokenly({
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 5,
        revokeOnSecurityBreach: true
    }
});

// Monitor security events
tokenly.on('invalid_fingerprint', async (event) => {
    console.log('Potential token theft detected:', event);
    await notifySecurityTeam(event);
});
```

### Token Rotation

```typescript
const tokenly = new Tokenly({
    rotationConfig: {
        checkInterval: 60000,      // Check every minute
        rotateBeforeExpiry: 300000, // Rotate 5 minutes before expiry
        maxRotationCount: 100      // Maximum rotation count
    }
});
```

## Next Steps

1. Read the [Security Guide](/guide/security) for best practices
2. Explore the [API Reference](/api/tokenly) for detailed documentation
3. Configure [Token Settings](/api/configuration) for your needs
4. Implement [Error Handling](/guide/security#error-handling)

## Common Issues

### CORS Configuration

```typescript
import cors from 'cors';

app.use(cors({
    origin: 'https://your-frontend.com',
    credentials: true
}));
```

### Production Setup

```typescript
const tokenly = new Tokenly({
    accessTokenExpiry: '5m',
    refreshTokenExpiry: '1d',
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 3,
        revokeOnSecurityBreach: true
    },
    cookieConfig: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});
```

## Support

- [GitHub Issues](https://github.com/nekzus/tokenly/issues)
- [Documentation](https://tokenly.dev)
