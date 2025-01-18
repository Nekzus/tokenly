import 'dotenv/config';
import { Tokenly } from './dist/index.js';

// Usage example
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    domain: '.yourdomain.com',
    path: '/api',
  },
  jwtOptions: {
    algorithm: 'HS512',
    issuer: 'tokenly',
    audience: 'api',
  },
});

// Test payload
const payload = {
  userId: 1,
  email: 'test@example.com',
  roles: ['user'],
};

// Generate initial tokens
const accessToken = tokenly.generateAccessToken(payload);
const refreshToken = tokenly.generateRefreshToken(payload);

console.log('Access Token:', accessToken);
console.log('Refresh Token (with cookie config):', refreshToken);

// Example of token rotation
const { accessToken: newAccess, refreshToken: newRefresh } = tokenly.rotateTokens(refreshToken.raw);

console.log('New Access Token:', newAccess);
console.log('New Refresh Token:', newRefresh);
