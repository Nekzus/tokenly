# Advanced Concepts

Quick access to key concepts and features in Tokenly.

## Security Features

- [Device Fingerprinting](/guide/security#device-management)
- [Token Rotation](/guide/security#token-rotation)
- [Multi-Device Support](/guide/security#device-management)
- [Session Management](/guide/security#session-management)

## Token Management

```ts
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    rotateRefreshToken: true,
    refreshTokenRotationInterval: '24h'
  }
})
```

## Error Handling

```ts
try {
  const verified = await tokenly.verifyAccessToken(token)
} catch (error) {
  if (error instanceof TokenlyError) {
    switch (error.code) {
      case 'TOKEN_EXPIRED':
      case 'TOKEN_INVALID':
      case 'FINGERPRINT_MISMATCH':
        // Handle specific errors
        break
    }
  }
}
```

## Quick References

- [Type Safety Guide](/guide/getting-started#type-safety)
- [Configuration Options](/guide/getting-started#configuration-options)
- [Best Practices](/guide/security#best-practices)
- [API Reference](/api/tokenly) 