# Tokenly

[![CI/CD & Publish](https://github.com/Nekzus/tokenly/actions/workflows/publish.yml/badge.svg)](https://github.com/Nekzus/tokenly/actions/workflows/publish.yml)
[![npm version](https://img.shields.io/npm/v/@nekzus/tokenly.svg)](https://www.npmjs.com/package/@nekzus/tokenly)
[![SLSA Provenance Level 3](https://img.shields.io/badge/SLSA-Level%203-blue.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Nekzus/tokenly/blob/main/LICENSE.md)

Secure JWT token management with advanced device fingerprinting for Node.js, Express, Fastify, and TypeScript applications.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [API Reference](#api-reference)
- [Environment Variables](#environment-variables)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Zero Configuration Required**: Works out of the box with secure defaults.
- **Device Fingerprinting**: Unique identification of devices to prevent token theft and session hijacking.
- **Framework Agnostic**: Compatible with Express, Fastify, Koa, or any Node.js server.
- **TypeScript First**: Full type safety and strict typings included natively.
- **SLSA Level 3 Provenance**: All releases built and published via GitHub Actions OIDC Trusted Publishing with verifiable supply chain attestations.

## Installation

Using `pnpm`:

```bash
pnpm add @nekzus/tokenly
```

Required dependency for HttpOnly cookie handling:

```bash
pnpm add cookie-parser
```

## Quick Start

```typescript
import { Tokenly, getClientIP } from "@nekzus/tokenly";
import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cookieParser());

const auth = new Tokenly({
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  securityConfig: {
    enableFingerprint: true,
    maxDevices: 5,
  },
});

app.post("/login", (req, res) => {
  const token = auth.generateAccessToken(
    { userId: "123", role: "user" },
    undefined,
    {
      userAgent: req.headers["user-agent"] || "",
      ip: getClientIP(req.headers),
    }
  );
  res.json({ token });
});
```

## Configuration

### Basic Configuration

```typescript
const auth = new Tokenly({
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  securityConfig: {
    enableFingerprint: true,
    maxDevices: 5,
  },
});
```

### Advanced Security Configuration

```typescript
const auth = new Tokenly({
  accessTokenExpiry: "5m",
  refreshTokenExpiry: "1d",
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 3,
  },
});
```

## Security Features

### Device Fingerprinting

- **User Agent**: Client identification header.
- **IP Address**: Client IPv4 or IPv6 address.
- **Cryptographic Salt**: Unique per instance.
- **Consistent Hashing**: Same device = Same fingerprint.

### Security Events

```typescript
auth.on("invalid_fingerprint", (event) => {
  console.log(`Security Alert: Invalid fingerprint detected for user ${event.userId}`);
});

auth.on("max_devices_reached", (event) => {
  console.log(`Device limit reached for user: ${event.userId}`);
});
```

## API Reference

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
import { getClientIP } from "@nekzus/tokenly";

const clientIP = getClientIP(headers, defaultIP);
```

Header evaluation priority:
1. `X-Real-IP`
2. `X-Forwarded-For`
3. Fallback IP

## Environment Variables

```env
JWT_SECRET_ACCESS=your_secure_access_token_secret
JWT_SECRET_REFRESH=your_secure_refresh_token_secret
```

> **Important**: When environment variables are omitted, Tokenly generates cryptographically secure secrets in memory. For production persistence, always supply permanent secrets via environment variables.

## Best Practices

- Use short-lived access tokens (5-15 minutes).
- Store refresh tokens in HttpOnly, Secure, SameSite cookies.
- Enable fingerprinting for sensitive applications.
- Enforce mandatory GPG signed commits for contributions.

## Contributing

See our [Contributing Guide](https://github.com/Nekzus/tokenly/blob/main/CONTRIBUTING.md) and [Code of Conduct](https://github.com/Nekzus/tokenly/blob/main/CODE_OF_CONDUCT.md).

## License

[MIT](https://github.com/Nekzus/tokenly/blob/main/LICENSE.md) © [Nekzus](https://github.com/Nekzus)
