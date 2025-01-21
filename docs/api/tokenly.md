# Tokenly API

## Overview

Tokenly is a secure JWT token manager that provides:

- 🔐 JWT token generation and validation
- 📱 Device fingerprinting
- 🔄 Token rotation
- 🚫 Token blacklisting
- 🖥️ Device limits per user
- 🍪 HttpOnly cookie support

## Installation

```bash
npm install @nekzus/tokenly
```

## Quick Start

```typescript
import { Tokenly } from '@nekzus/tokenly';

// Initialize with configuration
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

// Express example
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await authenticate(username, password);

    // Generate access token with device context
    const accessToken = tokenly.generateAccessToken(
        { userId: user.id },
        undefined,
        {
            userAgent: req.headers['user-agent'],
            ip: req.ip
        }
    );

    // Generate refresh token
    const refreshToken = tokenly.generateRefreshToken({ userId: user.id });

    // Set refresh token cookie if configured
    if (refreshToken.cookieConfig) {
        res.cookie(
            refreshToken.cookieConfig.name,
            refreshToken.cookieConfig.value,
            refreshToken.cookieConfig.options
        );
    }

    res.json({ token: accessToken.raw });
});
```

## Core Methods

### generateAccessToken

Generates a new access token with optional device fingerprinting.

```typescript
generateAccessToken(
    payload: TokenlyPayload,
    options?: jwt.SignOptions,
    context?: TokenlyContext
): TokenlyResponse
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `payload` | `TokenlyPayload` | Yes | Token payload with userId |
| `options` | `jwt.SignOptions` | No | JWT sign options |
| `context` | `TokenlyContext` | No | Device context |

#### Returns

```typescript
interface TokenlyResponse {
    raw: string;              // JWT token string
    payload: TokenlyPayload;  // Decoded payload
    cookieConfig?: {          // Cookie configuration
        name: string;
        value: string;
        options: CookieConfig;
    };
}
```

### generateRefreshToken

Generates a new refresh token with HttpOnly cookie configuration.

```typescript
generateRefreshToken(
    payload: TokenlyPayload,
    options?: jwt.SignOptions
): TokenlyResponse
```

### verifyAccessToken

Verifies an access token and validates device fingerprint if enabled.

```typescript
verifyAccessToken(
    token: string,
    context?: TokenlyContext
): TokenlyResponse
```

### rotateTokens

Rotates access and refresh tokens while maintaining security context.

```typescript
rotateTokens(refreshToken: string): TokenRotationResponse
```

#### Returns

```typescript
interface TokenRotationResponse {
    accessToken: TokenlyResponse;
    refreshToken: TokenlyResponse;
}
```

## Security Features

### Device Fingerprinting

```typescript
const token = tokenly.generateAccessToken(
    { userId: '123' },
    undefined,
    {
        userAgent: req.headers['user-agent'],
        ip: req.ip
    }
);
```

### Token Analysis

```typescript
const analysis = tokenly.analyzeTokenSecurity(token);
console.log(analysis);
/* Output:
{
    algorithm: "HS512",
    hasFingerprint: boolean,
    expirationTime: Date,
    issuedAt: Date,
    timeUntilExpiry: number,
    strength: "strong" | "medium" | "weak"
}
*/
```

### Auto Rotation

```typescript
// Enable auto rotation
tokenly.enableAutoRotation({
    checkInterval: 60000,      // 1 minute
    rotateBeforeExpiry: 300000 // 5 minutes
});

// Disable auto rotation
tokenly.disableAutoRotation();
```

## Event System

```typescript
// Token revocation
tokenly.on('token_revoked', (event: TokenRevokedEvent) => {
    console.log('Token revoked:', event);
});

// Device limit reached
tokenly.on('max_devices', (event: MaxDevicesEvent) => {
    console.log('Max devices reached:', event);
});

// Invalid fingerprint
tokenly.on('invalid_fingerprint', (event: InvalidFingerprintEvent) => {
    console.log('Invalid fingerprint:', event);
});

// Token expiring
tokenly.on('token_expiring', (event: TokenExpiringEvent) => {
    console.log('Token expiring:', event);
});
```

## Error Handling

```typescript
try {
    const verified = tokenly.verifyAccessToken(token);
} catch (error) {
    if (error instanceof TokenlyError) {
        switch (error.code) {
            case 'TOKEN_EXPIRED':
            case 'TOKEN_INVALID':
            case 'FINGERPRINT_MISMATCH':
            case 'MAX_DEVICES_REACHED':
                // Handle specific errors
                break;
        }
    }
}
```