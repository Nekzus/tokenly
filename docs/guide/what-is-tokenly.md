# What is Tokenly?

Tokenly is a JWT (JSON Web Tokens) Management System designed to build secure and robust authentication systems. At its core, Tokenly takes standard JWT handling and enhances it with enterprise-grade security features, including device fingerprinting, automatic token rotation, and multiple session management.

## Use Cases

* **API Authentication**  
Tokenly is optimized for REST and GraphQL APIs, providing a robust security layer with minimal configuration. It's used in production by APIs requiring high security and granular session control.

* **Web and Mobile Applications**  
The device fingerprinting system and multiple session management make Tokenly ideal for applications that need to control access from different devices and detect unauthorized token usage.

## Developer Experience

Tokenly is designed to provide an excellent Developer Experience (DX):

* **Zero-Config:** works out of the box with secure defaults
* **Fully Typed:** complete TypeScript support with exhaustive types
* **Intuitive API:** clear and concise methods for all common operations
* **Detailed Documentation:** comprehensive guides and API reference

## Performance

Tokenly is optimized for performance without compromising security:

* **Fast Generation:** optimized algorithms for token generation
* **Efficient Validation:** quick token verification with built-in caching
* **Minimal Footprint:** optimized bundle size with no unnecessary dependencies
* **Memory Management:** automatic cleanup of expired tokens and blacklists

## Security Features

Tokenly's primary focus is security:

* **Device Fingerprinting**  
Each token is cryptographically bound to the device that generated it, automatically detecting token theft attempts.

* **Automatic Rotation**  
Built-in token rotation system that allows token renewal before expiration, reducing the vulnerability window.

* **Device Management**  
Granular control over how many devices can be active simultaneously per user, with automatic revocation of old sessions.

* **Security Events**  
Comprehensive event system that allows monitoring and reacting to security incidents in real-time.

## Comparison with Alternatives

Unlike standard JWT libraries, Tokenly provides:

* Built-in device fingerprinting
* Automatic multiple session management
* Token rotation system
* Real-time security events
* Token security analysis
* Secure configuration by default

## Why Tokenly?

Tokenly was born from the need to have a token management system that was secure by default but flexible for advanced use cases. While traditional JWT libraries focus only on token generation and verification, Tokenly provides a complete ecosystem for secure authentication management.

::: tip Did You Know?
Tokenly automatically generates secure secrets if none are provided, meaning you can start developing without worrying about initial security configuration.
:::

::: warning Note
While Tokenly works with zero-config in development, for production it's recommended to explicitly configure secrets and expiration times.
:::

## Core Principles

1. **Security First**
   - Secure by default configuration
   - Proactive security measures
   - Real-time threat detection

2. **Developer Friendly**
   - Intuitive API design
   - Comprehensive documentation
   - Helpful error messages

3. **Enterprise Ready**
   - Scalable architecture
   - Performance optimized
   - Production-grade security

4. **Flexible Integration**
   - Framework agnostic
   - Customizable security rules
   - Extensible event system 