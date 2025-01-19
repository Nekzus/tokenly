# Tokenly

A secure JWT token manager with HttpOnly cookie support for modern web applications.

[![npm version](https://badge.fury.io/js/@nekzus%2Ftokenly.svg)](https://badge.fury.io/js/@nekzus%2Ftokenly)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Features

- 🔐 **Advanced Security**
  - JWT token management with HS512 algorithm
  - HttpOnly cookie support
  - Automatic token rotation
  - Token blacklisting
  
- 🔄 **Device Management**
  - Configurable device limits
  - Duplicate device detection
  - Per-device token revocation

## 📦 Installation

```bash
npm install @nekzus/tokenly
# or
yarn add @nekzus/tokenly
# or
pnpm add @nekzus/tokenly
```

## 🚀 Basic Usage

```typescript
import { Tokenly } from '@nekzus/tokenly';

// Basic initialization
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 5
  }
});

// Generate access token
const accessToken = tokenly.generateAccessToken({
  userId: '123',
  role: 'user'
});

// Verify token
const verified = tokenly.verifyAccessToken(accessToken.raw);
```

## 🔧 Configuration

### Available Options

```typescript
interface TokenlyConfig {
  accessTokenExpiry?: string;
  refreshTokenExpiry?: string;
  cookieOptions?: {
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
    maxAge?: number;
  };
  jwtOptions?: {
    algorithm?: jwt.Algorithm;
    audience?: string | string[];
    issuer?: string;
  };
  securityConfig?: {
    enableFingerprint?: boolean;
    enableBlacklist?: boolean;
    maxDevices?: number;
    revokeOnSecurityBreach?: boolean;
  };
}
```

### Environment Variables

```env
JWT_SECRET_ACCESS=your-secure-access-token-secret
JWT_SECRET_REFRESH=your-secure-refresh-token-secret
```

## 🔄 Automatic Rotation

```typescript
// Enable automatic rotation
tokenly.enableAutoRotation({
  checkInterval: 50000,    // Check interval in ms
  rotateBeforeExpiry: 1000 // Rotate tokens before expiry (ms)
});

// Disable rotation
tokenly.disableAutoRotation();
```

## 📊 Events

```typescript
// Listen for token events
tokenly.on('tokenExpiring', (data) => {
  console.log('Token about to expire:', data);
});

tokenly.on('maxDevicesReached', (data) => {
  console.log('Maximum devices reached:', data);
});
```

## 🔍 Error Handling

```typescript
try {
  const token = tokenly.generateAccessToken({
    userId: '123',
    role: 'user'
  });
} catch (error) {
  console.error('Error generating token:', error.message);
}
```

## 📚 Responses

### TokenlyResponse

```typescript
interface TokenlyResponse {
  raw: string;           // Raw JWT token
  payload: {             // Decoded payload
    [key: string]: any;
    iat?: Date;         // Issued at
    exp?: Date;         // Expires at
  };
  cookieConfig?: {      // Cookie configuration (if applicable)
    name: string;
    value: string;
    options: TokenlyOptions;
  };
}
```

## 🤝 Contributing

Contributions are welcome. Please open an issue or pull request.

## 📄 License

MIT © [Nekzus](https://github.com/Nekzus)

