import 'dotenv/config';
import { Tokenly } from './dist/index.esm.js';

interface TokenPayload {
  userId: number;
  email: string;
  roles: string[];
}

// Usage example
const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict' as const,
    domain: '.yourdomain.com',
    path: '/api',
  },
  jwtOptions: {
    algorithm: 'HS512',
    issuer: 'tokenly',
    audience: 'api',
  },
});

// Test payload with type
const payload: TokenPayload = {
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

// Verify token
const verifiedPayload = tokenly.verifyAccessToken(accessToken.raw);
console.log('Verified Payload:', verifiedPayload); 