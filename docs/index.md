---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Tokenly"
  text: "Advanced JWT Token Management"
  tagline: Enterprise-grade security with zero configuration
  image:
    src: /logo-light.svg
    alt: Tokenly Security Shield
    light: /logo-light.svg
    dark: /logo-dark.svg
  actions:
    - theme: brand
      text: Get Started
      link: /guide/what-is-tokenly
    - theme: alt
      text: API Reference
      link: /api/tokenly
    - theme: alt
      text: View on GitHub
      link: https://github.com/nekzus/tokenly

features:
  - icon: 🛡️
    title: Security First
    details: Built with enterprise-grade security features including device fingerprinting, token rotation, and real-time threat detection.
    link: /guide/security
    linkText: Learn about security
    
  - icon: ⚡️
    title: Zero Configuration
    details: Get started in minutes with secure defaults. No complex setup required, just install and start building.
    link: /guide/getting-started
    linkText: Quick start guide
    
  - icon: 🎯
    title: Type Safe
    details: Full TypeScript support with comprehensive types. Catch errors at compile time and enhance your development experience.
    link: /guide/type-safety
    linkText: View types
    
  - icon: 🔄
    title: Token Lifecycle
    details: Automatic token rotation, expiration management, and session control. Keep your authentication system secure and efficient.
    link: /guide/security#token-rotation
    linkText: Token management
    
  - icon: 📱
    title: Multi-Device Support
    details: Control and monitor user sessions across multiple devices. Automatic device fingerprinting and session management.
    link: /guide/security#device-management
    linkText: Device features
    
  - icon: 🚀
    title: High Performance
    details: Optimized for production with minimal overhead. Fast token generation and validation with built-in caching.
    link: /guide/getting-started#performance
    linkText: Performance guide

---

<style>
.custom-blocks {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin: 2rem 0;
}

.custom-block {
  padding: 20px;
  border-radius: 8px;
  background-color: var(--vp-c-bg-soft);
  transition: transform 0.2s, box-shadow 0.2s;
}

.custom-block:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.custom-block h3 {
  margin-top: 0;
  font-size: 1.2rem;
  display: flex;
  align-items: center;
  gap: 8px;
}

.custom-block p {
  margin-bottom: 0;
  opacity: 0.8;
}

.vp-doc {
  max-width: 1152px;
  margin: 0 auto;
  padding: 2rem;
}
</style>
