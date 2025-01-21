# Device Management

Device management is built into Tokenly's core token system, providing automatic device tracking and security features through token fingerprinting.

::: tip What is Device Fingerprinting?
Device fingerprinting is a technique that helps identify and track devices through their unique characteristics, strengthening token-based authentication systems.
:::

## Overview

Device tracking is handled automatically through token fingerprinting when generating tokens. Each token includes a secure device fingerprint that helps identify and validate devices during authentication.

## Configuration

Configure device management through the `securityConfig` options when initializing Tokenly:

```ts
import { Tokenly } from 'tokenly'

const tokenly = new Tokenly({
  securityConfig: {
    enableFingerprint: true,     // Enable device fingerprinting (default: true)
    enableBlacklist: true,       // Enable token blacklisting (default: true)
    maxDevices: 5,              // Maximum devices per user (default: 5)
    revokeOnSecurityBreach: true // Auto-revoke on security issues (default: true)
  }
})
```

## Device Fingerprinting

Device fingerprints are automatically generated when creating tokens if you provide the context:

```ts
const token = tokenly.generateAccessToken(payload, options, {
  userAgent: request.headers['user-agent'],
  ip: request.ip
})

// The token payload will include a device fingerprint
console.log(token.payload)
/* Output:
{
  userId: "123",
  fingerprint: "a1b2c3...", // Secure device fingerprint
  iat: "2024-03-21T...",
  exp: "2024-03-21T..."
}
*/
```

## Security Features

The device management system provides:

- Automatic device fingerprinting
- Device limits per user (default: 5 devices)
- Token blacklisting
- Automatic token revocation on security breaches
- Device validation during token verification

## Token Verification

Device validation happens automatically during token verification:

```ts
// Verify token with device context
const verified = tokenly.verifyAccessToken(token, {
  userAgent: request.headers['user-agent'],
  ip: request.ip
})

// Throws error if device fingerprint doesn't match
```

## Security Analysis

You can analyze token security including device fingerprint status:

```ts
const analysis = tokenly.analyzeTokenSecurity(token)
console.log(analysis)
/* Output:
{
  algorithm: "HS512",
  hasFingerprint: true,
  expirationTime: Date,
  issuedAt: Date,
  timeUntilExpiry: number,
  strength: "strong" | "medium" | "weak"
}
*/
```

## Best Practices

::: tip Best Practices
1. Always provide device context when generating tokens
2. Keep default security settings enabled
3. Use the built-in device limits
4. Implement proper error handling for device-related errors
5. Monitor token security analysis results
:::

## Security Considerations

::: warning Security Notes
- Device fingerprints are one-way hashes and cannot be reversed
- Fingerprints may change if user agent or IP changes
- Maximum device limits help prevent token abuse
- Token revocation is automatic on security breaches when enabled
:::

## Related

<div class="vp-doc">
  <div class="custom-block info">
    <p>
      📚 <a href="/guide/security">Security Guide</a><br>
      🔄 <a href="/guide/token-rotation">Token Rotation</a><br>
      🌐 <a href="/api/utils/ip-helper">IP Helper</a>
    </p>
  </div>
</div>
