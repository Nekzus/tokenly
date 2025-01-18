import { beforeEach, describe, expect, test } from 'vitest';
import { Tokenly } from '../src';

describe('Tokenly', () => {
  let tokenly: Tokenly;
  const mockContext = {
    userAgent: 'Mozilla/5.0',
    ip: '127.0.0.1'
  };

  beforeEach(() => {
    process.env.JWT_SECRET_ACCESS = 'test-secret-access';
    process.env.JWT_SECRET_REFRESH = 'test-secret-refresh';
    process.env.ACCESS_TOKEN_EXPIRY = '15m';
    process.env.REFRESH_TOKEN_EXPIRY = '7d';
    tokenly = new Tokenly();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      const defaultTokenly = new Tokenly();
      const token = defaultTokenly.generateAccessToken({ userId: '123' });
      expect(token).toHaveProperty('raw');
    });

    test('should initialize with custom config', () => {
      const customConfig = {
        accessTokenExpiry: '30m',
        refreshTokenExpiry: '14d',
        cookieOptions: {
          httpOnly: true,
          secure: false,
        },
        jwtOptions: {
          algorithm: 'HS512' as const,
          issuer: 'test-issuer',
        },
        securityConfig: {
          enableFingerprint: true,
          enableBlacklist: true,
          maxDevices: 3,
          revokeOnSecurityBreach: true,
        }
      };

      const customTokenly = new Tokenly(customConfig);
      const token = customTokenly.generateAccessToken({ userId: '123' });
      expect(token).toHaveProperty('raw');
    });
  });

  describe('Token Generation and Verification', () => {
    test('should generate and verify access token with fingerprint', () => {
      const payload = { userId: '123' };
      const token = tokenly.generateAccessToken(payload, undefined, mockContext);
      
      expect(token.raw).toBeDefined();
      expect(token.payload).toHaveProperty('fingerprint');
      
      const verified = tokenly.verifyAccessToken(token.raw, mockContext);
      expect(verified.payload).toMatchObject(expect.objectContaining(payload));
    });

    test('should detect invalid fingerprint', () => {
      const payload = { userId: '123' };
      const token = tokenly.generateAccessToken(payload, undefined, mockContext);
      
      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...mockContext,
          ip: '192.168.1.1'
        });
      }).toThrow('Invalid token fingerprint');
    });

    test('should throw error when verifying invalid token', () => {
      expect(() => {
        tokenly.verifyAccessToken('invalid.token.here');
      }).toThrow();
    });
  });

  describe('Refresh Token Management', () => {
    test('should generate and verify refresh token', () => {
      const payload = { userId: '123' };
      const refreshToken = tokenly.generateRefreshToken(payload);

      expect(refreshToken).toHaveProperty('raw');
      expect(refreshToken).toHaveProperty('cookieConfig');

      const verified = tokenly.verifyRefreshToken(refreshToken.raw);
      expect(verified.payload).toMatchObject(expect.objectContaining(payload));
    });

    test('should handle token rotation', () => {
      const payload = { userId: '123' };
      const refreshToken = tokenly.generateRefreshToken(payload);
      const rotated = tokenly.rotateTokens(refreshToken.raw);
      
      expect(rotated.accessToken.raw).toBeDefined();
      expect(rotated.refreshToken.raw).toBeDefined();
    });

    test('should throw error when rotating invalid refresh token', () => {
      expect(() => {
        tokenly.rotateTokens('invalid.token.here');
      }).toThrow();
    });
  });

  describe('Security Features', () => {
    test('should handle token revocation', () => {
      const payload = { userId: '123' };
      const token = tokenly.generateAccessToken(payload);
      
      tokenly.revokeToken(token.raw);
      
      expect(() => {
        tokenly.verifyAccessToken(token.raw);
      }).toThrow('Token has been revoked');
    });

    test('should enforce max devices limit', () => {
      const customTokenly = new Tokenly({
        securityConfig: {
          maxDevices: 2,
          enableFingerprint: true,
          enableBlacklist: true,
          revokeOnSecurityBreach: true
        }
      });

      const devices = [
        { userAgent: 'Mozilla/5.0', ip: '192.168.1.1' },
        { userAgent: 'Chrome/90.0', ip: '192.168.1.2' },
        { userAgent: 'Safari/14.0', ip: '192.168.1.3' }
      ];

      // Generar tokens para los primeros dos dispositivos
      devices.slice(0, 2).forEach(device => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, device)
      );

      // El tercer dispositivo debería fallar
      expect(() => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, devices[2])
      ).toThrow('Maximum number of devices reached');
    });
  });

  describe('Local Token Storage', () => {
    test('should store and retrieve token', () => {
      const token = 'test-token';
      tokenly.setToken(token);
      expect(tokenly.getToken()).toBe(token);
    });

    test('should clear stored token', () => {
      const token = 'test-token';
      tokenly.setToken(token);
      tokenly.clearToken();
      expect(tokenly.getToken()).toBeNull();
    });

    test('should return null when no token is stored', () => {
      expect(tokenly.getToken()).toBeNull();
    });
  });

  describe('Advanced Security Features', () => {
    test('should handle token expiration correctly', async () => {
      const customTokenly = new Tokenly({
        accessTokenExpiry: '1ms'
      });
      
      const token = customTokenly.generateAccessToken({ userId: '123' });
      
      // Esperar a que expire
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Verificar token expirado
      expect(() => customTokenly.verifyAccessToken(token.raw)).toThrow('jwt expired');
    });

    test('should handle concurrent device management', () => {
      const customTokenly = new Tokenly({
        securityConfig: {
          maxDevices: 2,
          enableFingerprint: true,
          enableBlacklist: true,
          revokeOnSecurityBreach: true
        }
      });

      const devices = [
        { userAgent: 'Mozilla/5.0', ip: '192.168.1.1' },
        { userAgent: 'Chrome/90.0', ip: '192.168.1.2' },
        { userAgent: 'Safari/14.0', ip: '192.168.1.3' }
      ];

      // Generar tokens para los primeros dos dispositivos
      const tokens = devices.slice(0, 2).map(device => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, device)
      );

      // Intentar generar un token para un tercer dispositivo
      expect(() => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, devices[2])
      ).toThrow('Maximum number of devices reached');
    });

    test('should handle token rotation with security checks', () => {
      const customTokenly = new Tokenly({
        rotationConfig: {
          enableAutoRotation: true,
          rotationInterval: 1,
          maxRotationCount: 2
        }
      });

      let currentToken = customTokenly.generateRefreshToken({ userId: '123' });

      // Realizar rotaciones hasta alcanzar el límite
      for (let i = 0; i < 2; i++) {
        const rotated = customTokenly.rotateTokens(currentToken.raw);
        currentToken = rotated.refreshToken;
      }

      // La siguiente rotación debería fallar
      expect(() => customTokenly.rotateTokens(currentToken.raw))
        .toThrow('Maximum rotation count exceeded');
    });
  });

  describe('Cookie Security', () => {
    test('should generate secure cookie configuration', () => {
      const customTokenly = new Tokenly({
        cookieOptions: {
          secure: true,
          httpOnly: true,
          sameSite: 'strict',
          domain: 'example.com',
          path: '/api'
        }
      });

      const token = customTokenly.generateRefreshToken({ userId: '123' });
      
      expect(token.cookieConfig).toBeDefined();
      expect(token.cookieConfig?.options).toMatchObject({
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        domain: 'example.com',
        path: '/api'
      });
    });

    test('should handle cookie options in production mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const tokenly = new Tokenly();
      const token = tokenly.generateRefreshToken({ userId: '123' });

      expect(token.cookieConfig?.options.secure).toBe(true);
      expect(token.cookieConfig?.options.sameSite).toBe('strict');

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Fingerprint Validation', () => {
    test('should validate complex fingerprint scenarios', () => {
      const contexts = [
        {
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X)',
          ip: '192.168.1.1'
        },
        {
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X)',
          ip: '192.168.1.1',
          additionalData: 'some-device-id'
        }
      ];

      const token1 = tokenly.generateAccessToken({ userId: '123' }, undefined, contexts[0]);
      const token2 = tokenly.generateAccessToken({ userId: '123' }, undefined, contexts[1]);

      expect(token1.payload.fingerprint).not.toBe(token2.payload.fingerprint);
    });

    test('should handle fingerprint changes', () => {
      const context = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken({ userId: '123' }, undefined, context);

      // Cambio menor en User-Agent
      expect(() => tokenly.verifyAccessToken(token.raw, {
        ...context,
        userAgent: 'Mozilla/5.0 (Updated)'
      })).toThrow();

      // Cambio en IP
      expect(() => tokenly.verifyAccessToken(token.raw, {
        ...context,
        ip: '192.168.1.2'
      })).toThrow();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle malformed tokens gracefully', () => {
      const malformedTokens = [
        'invalid',
        'invalid.token',
        'invalid.token.structure',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', // Header only
        null,
        undefined,
        ''
      ];

      malformedTokens.forEach(token => {
        expect(() => tokenly.verifyAccessToken(token as string)).toThrow();
      });
    });

    test('should handle payload validation', () => {
      const invalidPayloads = [
        {},
        { userId: '' },
        { userId: null },
        { userId: undefined },
        { userId: Array(1000).fill('a').join('') }
      ];

      invalidPayloads.forEach(payload => {
        expect(() => tokenly.generateAccessToken(payload)).toThrow();
      });
    });
  });
});
