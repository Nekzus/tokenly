# Tokenly

Secure JWT token management for modern web applications with HttpOnly cookies support.

![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quick Start

```bash
npm install @nekzus/tokenly
```

## Key Features

- 🔒 **Secure by Default**: HttpOnly cookies, token rotation, blacklisting
- 🚀 **Easy Integration**: Simple API for both frontend and backend
- 🔄 **Auto-Refresh**: Automatic token rotation before expiration
- 📱 **Device Management**: Control concurrent sessions

## Basic Usage

### Backend Setup
```typescript
import { Tokenly } from '@nekzus/tokenly';

const auth = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    httpOnly: true,
    secure: true
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Validate user (your logic here)
  const user = await validateUser(email, password);
  
  // Generate tokens
  const access = auth.generateAccessToken({ userId: user.id });
  const refresh = auth.generateRefreshToken({ userId: user.id });
  
  // Set refresh token as HttpOnly cookie
  res.cookie('refresh_token', refresh.raw, refresh.cookieConfig.options);
  
  // Send access token in response
  res.json({ 
    accessToken: access.raw,
    user: user 
  });
});

// Refresh endpoint
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  
  try {
    const verified = auth.verifyRefreshToken(refreshToken);
    const { accessToken, refreshToken: newRefresh } = auth.rotateTokens(refreshToken);
    
    res.cookie('refresh_token', newRefresh.raw, newRefresh.cookieConfig.options);
    res.json({ accessToken: accessToken.raw });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});
```

### Frontend Integration
```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  withCredentials: true // Important for cookies
});

// Axios interceptor for auto refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const { data } = await api.post('/refresh');
      error.config.headers.Authorization = `Bearer ${data.accessToken}`;
      return api(error.config);
    }
    return Promise.reject(error);
  }
);

// Usage example
const login = async (email: string, password: string) => {
  const { data } = await api.post('/login', { email, password });
  localStorage.setItem('accessToken', data.accessToken);
  return data.user;
};

const getProtectedData = async () => {
  const token = localStorage.getItem('accessToken');
  const { data } = await api.get('/protected', {
    headers: { Authorization: `Bearer ${token}` }
  });
  return data;
};
```

## Advanced Configuration

```typescript
const auth = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  },
  securityConfig: {
    enableFingerprint: true,
    maxDevices: 5,
    revokeOnSecurityBreach: true
  }
});
```

## Security Features

- **HttpOnly Cookies**: Prevents XSS attacks
- **Token Rotation**: Automatic refresh before expiration
- **Device Fingerprinting**: Detect and limit concurrent sessions
- **Token Blacklisting**: Revoke compromised tokens
- **Auto Cleanup**: Automatic removal of expired tokens

## API Reference

### Token Generation
```typescript
const accessToken = auth.generateAccessToken(payload);
const refreshToken = auth.generateRefreshToken(payload);
```

### Token Verification
```typescript
const verified = auth.verifyAccessToken(token);
const refreshVerified = auth.verifyRefreshToken(token);
```

### Token Rotation
```typescript
const { accessToken, refreshToken } = auth.rotateTokens(currentRefreshToken);
```

### Event Handling
```typescript
auth.on('tokenExpiring', (data) => {
  console.log('Token about to expire:', data);
});
```

## Error Handling

```typescript
try {
  const verified = auth.verifyAccessToken(token);
} catch (error) {
  if (error.message === 'Token has been revoked') {
    // Handle revoked token
  }
  // Handle other errors
}
```

## TypeScript Support

Full TypeScript support with detailed type definitions included.

## License

MIT © [Nekzus](https://github.com/Nekzus)

