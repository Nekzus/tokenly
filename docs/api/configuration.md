# Configuration

## TokenlyConfig

Configuration options for initializing the Tokenly instance.

```ts
interface TokenlyConfig {
    accessTokenExpiry?: string;
    refreshTokenExpiry?: string;
    securityConfig?: SecurityConfig;
    rotationConfig?: RotationConfig;
    cookieConfig?: CookieConfig;
}
```

### Basic Configuration

```ts
const tokenly = new Tokenly({
    accessTokenExpiry: '15m',    // 15 minutes (default)
    refreshTokenExpiry: '7d',    // 7 days (default)
});
```

### Security Configuration

```ts
interface SecurityConfig {
    enableFingerprint: boolean;     // Enable device fingerprinting
    enableBlacklist: boolean;       // Enable token blacklisting
    maxDevices: number;            // Max devices per user
    revokeOnSecurityBreach?: boolean; // Auto-revoke on security issues
}
```

#### Example
```ts
const tokenly = new Tokenly({
    securityConfig: {
        enableFingerprint: true,  // default: true
        enableBlacklist: true,    // default: true
        maxDevices: 5,           // default: 5
        revokeOnSecurityBreach: true // default: true
    }
});
```

### Cookie Configuration

```ts
interface CookieConfig {
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
    maxAge?: number;
}
```

#### Example
```ts
const tokenly = new Tokenly({
    cookieConfig: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
});
```

### Rotation Configuration

```ts
interface RotationConfig {
    checkInterval?: number;        // Check interval in milliseconds
    rotateBeforeExpiry?: number;   // Time before expiry to rotate
    maxRotationCount?: number;     // Maximum number of rotations
}
```

#### Example
```ts
const tokenly = new Tokenly({
    rotationConfig: {
        checkInterval: 60000,      // Check every minute
        rotateBeforeExpiry: 300000, // Rotate 5 minutes before expiry
        maxRotationCount: 100      // Maximum 100 rotations
    }
});
```

## Environment Variables

Tokenly supports configuration through environment variables:

```env
JWT_SECRET_ACCESS=your_secure_access_token_secret
JWT_SECRET_REFRESH=your_secure_refresh_token_secret
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

### Priority Order

1. Constructor options
2. Environment variables
3. Default values

## Best Practices

### Production Settings
```ts
const tokenly = new Tokenly({
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 5,
        revokeOnSecurityBreach: true
    },
    cookieConfig: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
    },
    rotationConfig: {
        checkInterval: 60000,
        rotateBeforeExpiry: 300000,
        maxRotationCount: 100
    }
});
```

### Development Settings
```ts
const tokenly = new Tokenly({
    accessTokenExpiry: '1h',     // Longer for testing
    refreshTokenExpiry: '7d',
    securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 10          // More lenient for testing
    }
});
```