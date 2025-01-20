# Tokenly 🔐

<div align="center">

[![npm version](https://badge.fury.io/js/@nekzus%2Ftokenly.svg)](https://www.npmjs.com/package/@nekzus/tokenly)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Secure JWT token management with advanced device fingerprinting**

_Security by default, enhanced with device fingerprinting_

</div>

## ✨ Features

- **🛡️ Security by Default**: JWT tokens with built-in security features
- **🔒 Device Control**: Advanced fingerprinting system for device tracking
- **🚀 Easy Integration**: Simple API that works seamlessly with Express
- **⚡ Performance**: Optimized token generation and validation
- **🛠️ Configurable**: Flexible settings to match your security needs

## 📦 Installation

```bash
npm install @nekzus/tokenly
```

## 🚀 Quick Start

```typescript
import { Tokenly } from '@nekzus/tokenly';

// Initialize with fingerprinting enabled
const auth = new Tokenly({
  accessTokenExpiry: '15m',
  securityConfig: {
    enableFingerprint: true,
    maxDevices: 5
  }
});

// Generate a token with device fingerprinting
const token = auth.generateAccessToken(
    { userId: '123' },
    undefined,
    {
        userAgent: req.headers['user-agent'] || '',
        ip: getClientIP(req)
    }
);
```

## 📘 API Reference

### Configuration

```typescript
interface TokenlyConfig {
    // Token expiration time (default: '15m')
    accessTokenExpiry?: string;
    
    // Security settings
    securityConfig?: {
        // Enable device fingerprinting (default: false)
        enableFingerprint?: boolean;
        // Maximum devices per user (default: 5)
        maxDevices?: number;
    };
}
```

### Token Generation

```typescript
// Helper for reliable IP detection
function getClientIP(req: express.Request): string {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string') {
        return forwardedFor.split(',')[0].trim();
    }
    return req.ip || '';
}

// Express implementation example
app.post('/login', async (req, res) => {
    try {
        const token = auth.generateAccessToken(
            { userId: user.id },
            undefined,
            {
                userAgent: req.headers['user-agent'] || '',
                ip: getClientIP(req)
            }
        );
        res.json({ token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
```

### Token Structure

```typescript
interface AccessToken {
    // JWT token string
    raw: string;
    
    // Token payload
    payload: {
        userId: string;
        fingerprint?: string;  // Present when fingerprinting is enabled
        aud: string;          // 'tokenly-client'
        iss: string;          // 'tokenly-auth'
        iat: string;          // Issue timestamp
        exp: string;          // Expiration timestamp
    };
}
```

## 🔒 Security Best Practices

### Device Fingerprinting
- **Unique Identification**: Each device is uniquely identified by its IP and User-Agent combination
- **Consistent Tracking**: Same device will generate the same fingerprint across sessions
- **Fraud Prevention**: Helps detect and prevent unauthorized access attempts

### IP Detection
- Always handle `X-Forwarded-For` headers properly in proxy environments
- Use the first IP in the chain as it represents the original client
- Implement appropriate fallbacks for direct connections

### User Agent Handling
- Use complete User-Agent strings for maximum accuracy
- Provide fallbacks for empty values
- Maintain original User-Agent format

## 📚 Examples

### Basic Implementation
```typescript
const auth = new Tokenly();

// Generate token
const token = auth.generateAccessToken({ userId: '123' });
```

### With Fingerprinting
```typescript
const auth = new Tokenly({
    securityConfig: { enableFingerprint: true }
});

// Generate token with device tracking
const token = auth.generateAccessToken(
    { userId: '123' },
    undefined,
    { userAgent, ip }
);
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT © [Nekzus](https://github.com/Nekzus)

