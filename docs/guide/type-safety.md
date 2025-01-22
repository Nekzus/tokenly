# Type Safety

Tokenly is built with TypeScript and provides comprehensive type safety out of the box. This guide explains how to leverage TypeScript features for a better development experience.

## Type Definitions

### Basic Types

```ts
import { Tokenly, TokenlyConfig, TokenPayload } from '@nekzus/tokenly';

// Basic configuration with type checking
const config: TokenlyConfig = {
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    enableFingerprint: true,
    maxDevices: 5
  }
};

// Initialize with type-safe config
const tokenly = new Tokenly(config);
```

### Token Payload Types

```ts
// Define your custom payload type
interface UserPayload extends TokenPayload {
  userId: string;
  role: 'admin' | 'user';
  permissions: string[];
}

// Generate token with typed payload
const token = tokenly.generateAccessToken<UserPayload>({
  userId: '123',
  role: 'admin',
  permissions: ['read', 'write']
});

// Type-safe token verification
const verified = tokenly.verifyAccessToken<UserPayload>(token);
console.log(verified.payload.role); // TypeScript knows this is 'admin' | 'user'
```

## Generic Type Parameters

### Response Types

```ts
import { TokenlyResponse, TokenRotationResponse } from '@nekzus/tokenly';

// Type-safe response handling
async function handleLogin(userId: string): Promise<TokenlyResponse<UserPayload>> {
  const token = await tokenly.generateAccessToken<UserPayload>({
    userId,
    role: 'user',
    permissions: ['read']
  });
  
  return token;
}

// Rotation with type safety
async function rotateTokens(refreshToken: string): Promise<TokenRotationResponse<UserPayload>> {
  const tokens = await tokenly.rotateTokens<UserPayload>(refreshToken);
  return tokens;
}
```

## Event Types

```ts
import { 
  TokenRevokedEvent,
  MaxDevicesEvent,
  TokenExpiringEvent 
} from '@nekzus/tokenly';

// Type-safe event handling
tokenly.on('token_revoked', (event: TokenRevokedEvent<UserPayload>) => {
  console.log(event.payload.userId); // TypeScript knows the shape of payload
});

tokenly.on('max_devices', (event: MaxDevicesEvent) => {
  console.log(event.userId, event.deviceCount);
});
```

## Error Types

```ts
import { TokenlyError, ErrorCode } from '@nekzus/tokenly';

try {
  const verified = tokenly.verifyAccessToken(token);
} catch (error) {
  if (error instanceof TokenlyError) {
    switch (error.code) {
      case ErrorCode.TOKEN_EXPIRED:
        // TypeScript knows all possible error codes
        handleExpiredToken();
        break;
      case ErrorCode.INVALID_FINGERPRINT:
        handleSecurityBreach();
        break;
    }
  }
}
```

## Configuration Types

### Security Config

```ts
import { SecurityConfig } from '@nekzus/tokenly';

const securityConfig: SecurityConfig = {
  enableFingerprint: true,
  enableBlacklist: true,
  maxDevices: 5,
  revokeOnSecurityBreach: true
};
```

### Cookie Config

```ts
import { CookieConfig } from '@nekzus/tokenly';

const cookieConfig: CookieConfig = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/'
};
```

## Type Guards

```ts
import { isTokenlyError, isValidPayload } from '@nekzus/tokenly';

function handleError(error: unknown) {
  if (isTokenlyError(error)) {
    // TypeScript knows this is a TokenlyError
    console.log(error.code, error.message);
  }
}

function processPayload(data: unknown) {
  if (isValidPayload<UserPayload>(data)) {
    // TypeScript knows this is a UserPayload
    console.log(data.userId, data.role);
  }
}
```

## Best Practices

1. **Always Define Custom Payloads**
```ts
// Define interfaces for your payloads
interface UserPayload extends TokenPayload {
  userId: string;
  role: string;
}

// Use them consistently
const token = tokenly.generateAccessToken<UserPayload>(payload);
```

2. **Use Strict TypeScript Configuration**
```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true
  }
}
```

3. **Leverage Type Inference**
```ts
// Let TypeScript infer complex types
const result = await tokenly.verifyAccessToken<UserPayload>(token);
// result.payload is automatically typed
```

## Type Safety Benefits

- Catch errors at compile time
- Better IDE support with autocompletion
- Self-documenting code
- Safer refactoring
- Reduced runtime errors

::: tip
Use TypeScript's strict mode for maximum type safety benefits.
:::

::: warning
Type safety only works during development. Always implement proper runtime validation.
::: 