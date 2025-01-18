import { beforeEach, describe, expect, test } from 'vitest';
import { Tokenly } from '../src';

describe('Tokenly', () => {
  let tokenly: Tokenly;

  beforeEach(() => {
    process.env.JWT_SECRET_ACCESS = 'test-secret-access';
    process.env.JWT_SECRET_REFRESH = 'test-secret-refresh';
    process.env.ACCESS_TOKEN_EXPIRY = '15m';
    process.env.REFRESH_TOKEN_EXPIRY = '7d';

    tokenly = new Tokenly();
  });

  describe('Initialization', () => {
    test('should initialize with custom config', () => {
      const customConfig = {
        accessTokenExpiry: '30m',
        refreshTokenExpiry: '14d',
        cookieOptions: {
          httpOnly: true,
          secure: false,
        },
        jwtOptions: {
          algorithm: 'HS256' as const,
          issuer: 'test-issuer',
        },
      };

      const customTokenly = new Tokenly(customConfig);
      const token = customTokenly.generateAccessToken({ userId: '123' });
      expect(token).toHaveProperty('raw');
    });
  });

  describe('Access Token Management', () => {
    test('should generate and verify an access token', () => {
      const payload = { userId: '123', role: 'user' };
      const tokenResponse = tokenly.generateAccessToken(payload);

      expect(tokenResponse).toHaveProperty('raw');
      expect(tokenResponse).toHaveProperty('payload');
      expect(tokenResponse).toHaveProperty('issuedAt');
      expect(tokenResponse).toHaveProperty('expiresAt');

      const verified = tokenly.verifyAccessToken(tokenResponse.raw);
      expect(verified.payload).toMatchObject(expect.objectContaining(payload));
    });

    test('should throw error when verifying invalid token', () => {
      expect(() => {
        tokenly.verifyAccessToken('invalid.token.here');
      }).toThrow();
    });

    test('should generate token with custom JWT options', () => {
      const payload = { userId: '123' };
      const jwtOptions = {
        issuer: 'test-issuer',
        audience: 'test-audience',
      };

      const token = tokenly.generateAccessToken(payload, jwtOptions);
      const verified = tokenly.verifyAccessToken(token.raw);

      expect(verified.payload).toHaveProperty('iss', 'test-issuer');
      expect(verified.payload).toHaveProperty('aud', 'test-audience');
    });
  });

  describe('Refresh Token Management', () => {
    test('should generate refresh token with cookie configuration', () => {
      const payload = { userId: '123' };
      const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'strict' as const,
        path: '/',
      };
      const tokenResponse = tokenly.generateRefreshToken(payload, cookieOptions);

      expect(tokenResponse).toHaveProperty('cookieConfig');
      expect(tokenResponse.cookieConfig).toHaveProperty('name', 'refresh_token');
      expect(tokenResponse.cookieConfig?.options).toHaveProperty('httpOnly', true);
    });

    test('should verify refresh token', () => {
      const payload = { userId: '123' };
      const refreshToken = tokenly.generateRefreshToken(payload);

      const verified = tokenly.verifyRefreshToken(refreshToken.raw);
      expect(verified.payload).toMatchObject(expect.objectContaining(payload));
    });

    test('should throw error when verifying invalid refresh token', () => {
      expect(() => {
        tokenly.verifyRefreshToken('invalid.token.here');
      }).toThrow();
    });

    test('should rotate tokens with new payload', () => {
      const originalPayload = { userId: '123', role: 'user' };
      const newPayload = { userId: '123', role: 'admin' };
      const refreshToken = tokenly.generateRefreshToken(originalPayload);

      const { accessToken } = tokenly.rotateTokens(
        refreshToken.raw,
        newPayload
      );

      const verifiedAccess = tokenly.verifyAccessToken(accessToken.raw);
      expect(verifiedAccess.payload).toMatchObject(expect.objectContaining(newPayload));
    });
  });

  describe('Local Token Storage', () => {
    test('should store and retrieve a token', () => {
      const token = 'my-test-token';
      tokenly.setToken(token);
      expect(tokenly.getToken()).toBe(token);
    });

    test('should return null when no token is stored', () => {
      expect(tokenly.getToken()).toBeNull();
    });

    test('should clear stored token', () => {
      const token = 'my-test-token';
      tokenly.setToken(token);
      tokenly.clearToken();
      expect(tokenly.getToken()).toBeNull();
    });
  });
});
