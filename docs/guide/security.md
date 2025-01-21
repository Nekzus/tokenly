# Security Guide

## Overview

Tokenly implements multiple security layers to protect your authentication system. This guide covers the security features and best practices.

## Device Fingerprinting

Device fingerprinting helps prevent token theft by binding tokens to specific devices:

```typescript
const tokenly = new Tokenly({
    securityConfig: {
        enableFingerprint: true  // Enabled by default
    }
});

// Token generation with device context
const token = tokenly.generateAccessToken(
    { userId: '123' },
    undefined,
    {
        userAgent: req.headers['user-agent'],
        ip: getClientIP(req.headers)
    }
);
```

The fingerprint is automatically validated during token verification:

```typescript
try {
    const verified = tokenly.verifyAccessToken(token, {
        userAgent: req.headers['user-agent'],
        ip: getClientIP(req.headers)
    });
} catch (error) {
    // Handle invalid fingerprint
}
```

## Token Security Analysis

Analyze token security characteristics:

```typescript
const analysis = tokenly.analyzeTokenSecurity(token);
/* Returns:
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

## Token Rotation

Implement secure token rotation to prevent token reuse:

```typescript
const tokenly = new Tokenly({
    rotationConfig: {
        checkInterval: 60000,        // Check every minute
        rotateBeforeExpiry: 300000,  // Rotate 5 minutes before expiry
        maxRotationCount: 100        // Maximum rotation count
    }
});

// Enable auto rotation
tokenly.enableAutoRotation();

// Manual rotation
const tokens = tokenly.rotateTokens(currentRefreshToken);
```

## Device Management

Control the number of active devices per user:

```typescript
const tokenly = new Tokenly({
    securityConfig: {
        maxDevices: 5,              // Maximum devices per user
        revokeOnSecurityBreach: true // Auto-revoke on security issues
    }
});
```

## Security Events

Monitor security-related activities:

```typescript
// Invalid fingerprint detection
tokenly.on('invalid_fingerprint', (event: InvalidFingerprintEvent) => {
    console.log('Invalid fingerprint:', event);
    // {
    //     token: string,
    //     expectedFingerprint: string,
    //     receivedFingerprint: string
    // }
});

// Maximum devices reached
tokenly.on('max_devices', (event: MaxDevicesEvent) => {
    console.log('Max devices reached:', event);
    // {
    //     userId: string,
    //     currentDevices: number,
    //     maxDevices: number
    // }
});

// Token revocation
tokenly.on('token_revoked', (event: TokenRevokedEvent) => {
    console.log('Token revoked:', event);
    // {
    //     token: string,
    //     userId: string,
    //     timestamp: number
    // }
});

// Token expiring
tokenly.on('token_expiring', (event: TokenExpiringEvent) => {
    console.log('Token expiring:', event);
    // {
    //     token: string,
    //     userId: string,
    //     expiresIn: number
    // }
});
```

## Production Configuration

Recommended security settings for production:

```typescript
const tokenly = new Tokenly({
    accessTokenExpiry: '5m',      // Short-lived access tokens
    refreshTokenExpiry: '1d',     // Daily refresh
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 3,
        revokeOnSecurityBreach: true
    },
    cookieConfig: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    },
    rotationConfig: {
        checkInterval: 60000,
        rotateBeforeExpiry: 300000,
        maxRotationCount: 100
    }
});
```

## Error Handling

Handle security-related errors:

```typescript
try {
    const verified = tokenly.verifyAccessToken(token);
} catch (error) {
    if (error.code === ErrorCode.INVALID_FINGERPRINT) {
        // Handle potential token theft
        await securityLogger.alert('Token theft attempt', error);
        await revokeAllUserTokens(userId);
    }
    if (error.code === ErrorCode.MAX_DEVICES_REACHED) {
        // Handle device limit exceeded
        await notifyUser(userId, 'Maximum devices reached');
    }
}
```

## Security Checklist

### Required Measures
- [x] Enable device fingerprinting
- [x] Configure secure cookies (httpOnly, secure, sameSite)
- [x] Implement token rotation
- [x] Set appropriate token expiry times
- [x] Enable security event monitoring
- [x] Configure maximum device limits

### Best Practices
- [x] Use HTTPS only in production
- [x] Implement proper error handling
- [x] Log security events
- [x] Monitor invalid fingerprint attempts
- [x] Configure auto-rotation for tokens
- [x] Enable automatic token revocation on security breaches

## Environment Variables

Secure configuration through environment variables:

```env
JWT_SECRET_ACCESS=your_secure_access_token_secret
JWT_SECRET_REFRESH=your_secure_refresh_token_secret
ACCESS_TOKEN_EXPIRY=5m
REFRESH_TOKEN_EXPIRY=1d
```

::: warning Note
If JWT secrets are not provided via environment variables, Tokenly will generate secure random secrets. However, these will change on server restart, invalidating all existing tokens.
:::