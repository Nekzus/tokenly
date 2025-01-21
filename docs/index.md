---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Tokenly"
  text: "Advanced JWT Token Management"
  tagline: Enterprise-grade security by default for modern applications
  image:
    src: /logo.png
    alt: Tokenly Logo
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/tokenly
    - theme: alt
      text: View on GitHub
      link: https://github.com/nekzus/tokenly

features:
  - icon: 🔐
    title: Zero Configuration
    details: Works out of the box with secure defaults. Auto-generates secure secrets if not provided.
    
  - icon: 📱
    title: Device Fingerprinting
    details: Built-in device fingerprinting to prevent token theft and unauthorized access.
    
  - icon: 🔄
    title: Token Rotation
    details: Automatic token rotation with configurable intervals and expiry warnings.
    
  - icon: 🛡️
    title: Framework Agnostic
    details: Works with any Node.js framework. Simple integration with Express, Fastify, or any HTTP server.
    
  - icon: 🚫
    title: Token Blacklisting
    details: Built-in token blacklisting with automatic cleanup of expired tokens.
    
  - icon: 🖥️
    title: Device Management
    details: Control active sessions with configurable device limits and automatic revocation.

  - icon: 🍪
    title: Secure Cookies
    details: HttpOnly cookies with secure defaults for refresh tokens.
    
  - icon: 📊
    title: Security Events
    details: Real-time monitoring of security events including fingerprint mismatches and device limits.

  - icon: 🔍
    title: Token Analysis
    details: Built-in security analysis of tokens with strength assessment.

---

## Quick Start

```bash
npm install @nekzus/tokenly
```

```typescript
import { Tokenly } from '@nekzus/tokenly';

const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 5
  }
});
```

## Why Tokenly?

- 🔒 **Security First**: Built with security best practices by default
- 🚀 **Performance**: Optimized token generation and validation
- 📦 **Modern**: Full TypeScript support with comprehensive types
- 🛠️ **Flexible**: Extensive configuration options
- 📘 **Well Documented**: Comprehensive guides and API reference

## Community

<div class="vp-doc">
  <div class="custom-block info">
    <p>
      🐛 <a href="https://github.com/nekzus/tokenly/issues">Issue Tracker</a><br>
      📝 <a href="https://github.com/nekzus/tokenly/blob/main/CHANGELOG.md">Changelog</a>
    </p>
  </div>
</div>
