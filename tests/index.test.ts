import { afterEach, beforeEach, describe, expect, it, test, vi } from 'vitest';
import { Tokenly } from '../src';
import { ErrorCode, ErrorMessages } from '../src/utils/errorHandler';

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
    it('should initialize with default config', () => {
      const tokenly = new Tokenly();
      expect(tokenly).toBeDefined();
    });

    it('should initialize with custom config', () => {
      const tokenly = new Tokenly({
        accessTokenExpiry: '30m',
        securityConfig: {
          enableFingerprint: true,
          maxDevices: 3
        }
      });
      expect(tokenly).toBeDefined();
    });
  });

  describe('Token Generation and Verification', () => {
    const tokenly = new Tokenly({
      securityConfig: { enableFingerprint: true }
    });

    it('should generate and verify access token with fingerprint', () => {
      const context = {
        userAgent: 'Mozilla/5.0 Test',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        context
      );

      expect(token.raw).toBeDefined();
      expect(token.payload.fingerprint).toBeDefined();
      expect(token.payload.userId).toBe('123');
    });

    it('should generate consistent fingerprints for same context', () => {
      const context = {
        userAgent: 'TestAgent',
        ip: '192.168.1.1'
      };

      const token1 = tokenly.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        context
      );

      const token2 = tokenly.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        context
      );

      expect(token1.payload.fingerprint).toBe(token2.payload.fingerprint);
    });

    it('should generate different fingerprints for different contexts', () => {
      const context1 = {
        userAgent: 'TestAgent1',
        ip: '192.168.1.1'
      };

      const context2 = {
        userAgent: 'TestAgent2',
        ip: '192.168.1.1'
      };

      const token1 = tokenly.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        context1
      );

      const token2 = tokenly.generateAccessToken(
        { userId: '123', role: 'user' },
        undefined,
        context2
      );

      expect(token1.payload.fingerprint).not.toBe(token2.payload.fingerprint);
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

      devices.slice(0, 2).forEach(device => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, device)
      );

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
      
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(() => customTokenly.verifyAccessToken(token.raw))
        .toThrow(ErrorMessages[ErrorCode.TOKEN_EXPIRED]);
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

      devices.slice(0, 2).forEach(device => 
        customTokenly.generateAccessToken({ userId: '123' }, undefined, device)
      );

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

      for (let i = 0; i < 2; i++) {
        const rotated = customTokenly.rotateTokens(currentToken.raw);
        currentToken = rotated.refreshToken;
      }

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

  describe('Fingerprint Generation and Validation', () => {
    test('should generate unique fingerprints for different device/IP combinations', () => {
      const testCases = [
        { userAgent: 'Mozilla/5.0', ip: '192.168.1.1' },
        { userAgent: 'Mozilla/5.0', ip: '192.168.1.2' },
        { userAgent: 'Chrome/90.0', ip: '192.168.1.1' },
        { userAgent: 'Safari/14.0', ip: '192.168.1.1' }
      ];

      const fingerprints = new Set();
      const tokensMap = new Map();

      testCases.forEach(context => {
        const token = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );

        expect(token.payload.fingerprint).toBeDefined();
        
        const key = `${context.userAgent}:${context.ip}`;
        tokensMap.set(key, token);
        fingerprints.add(token.payload.fingerprint);
      });

      expect(fingerprints.size).toBe(testCases.length);
    });

    test('should maintain consistent fingerprints for same device/IP', () => {
      const context = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const token1 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      const token2 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      const token3 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);

      expect(token1.payload.fingerprint).toBe(token2.payload.fingerprint);
      expect(token2.payload.fingerprint).toBe(token3.payload.fingerprint);
    });

    test('should reject tokens with mismatched fingerprints', () => {
      const originalContext = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const differentContext = {
        userAgent: 'Chrome/90.0',
        ip: '192.168.1.2'
      };

      const token = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        originalContext
      );

      expect(() => {
        tokenly.verifyAccessToken(token.raw, differentContext);
      }).toThrow('Invalid token fingerprint');
    });

    test('should handle complex fingerprint scenarios', () => {
      const baseContext = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X)',
        ip: '192.168.1.1'
      };

      const slightlyDifferentUA = {
        ...baseContext,
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4.1 like Mac OS X)'
      };

      const differentIP = {
        ...baseContext,
        ip: '192.168.1.2'
      };

      const token = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        baseContext
      );

      const tokenWithDifferentUA = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        slightlyDifferentUA
      );
      expect(tokenWithDifferentUA.payload.fingerprint).not.toBe(token.payload.fingerprint);

      const tokenWithDifferentIP = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        differentIP
      );
      expect(tokenWithDifferentIP.payload.fingerprint).not.toBe(token.payload.fingerprint);

      const tokenWithSameContext = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        baseContext
      );
      expect(tokenWithSameContext.payload.fingerprint).toBe(token.payload.fingerprint);
    });

    test('should handle fingerprint changes over time', async () => {
      const context = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      
      expect(() => {
        tokenly.verifyAccessToken(token.raw, context);
      }).not.toThrow();

      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(() => {
        tokenly.verifyAccessToken(token.raw, context);
      }).not.toThrow();

      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...context,
          userAgent: 'Mozilla/5.0 (Updated)'
        });
      }).toThrow('Invalid token fingerprint');
    });

    test('should handle partial context changes', () => {
      const originalContext = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        originalContext
      );

      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...originalContext,
          ip: '192.168.1.2'
        });
      }).toThrow('Invalid token fingerprint');

      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...originalContext,
          userAgent: 'Chrome/90.0'
        });
      }).toThrow('Invalid token fingerprint');
    });

    test('should handle invalid context values', () => {
      expect(() => {
        tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          { userAgent: '', ip: '' }
        );
      }).toThrow();

      expect(() => {
        tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          { userAgent: null as any, ip: null as any }
        );
      }).toThrow();

      expect(() => {
        tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          { userAgent: undefined as any, ip: undefined as any }
        );
      }).toThrow();
    });

    test('should handle special characters in context', () => {
      const specialCases = [
        {
          userAgent: 'Mozilla/5.0 (特殊文字)',
          ip: '192.168.1.1',
          description: 'Unicode characters'
        },
        {
          userAgent: 'Mozilla/5.0 (@#$%^&*)',
          ip: '192.168.1.1',
          description: 'Special characters'
        },
        {
          userAgent: 'Mozilla/5.0 (\n\t)',
          ip: '192.168.1.1',
          description: 'Whitespace characters'
        },
        {
          userAgent: 'Mozilla/5.0 ('.repeat(100),
          ip: '192.168.1.1',
          description: 'Long string'
        }
      ];

      specialCases.forEach(context => {
        const token = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );

        expect(token.payload.fingerprint).toBeDefined();
        expect(typeof token.payload.fingerprint).toBe('string');
        expect(token.payload.fingerprint.length).toBeGreaterThan(0);

        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();
      });
    });

    test('should handle edge cases in fingerprint generation', () => {
      const edgeCases = [
        {
          userAgent: 'Mozilla/5.0',
          ip: '::1',
          description: 'IPv6 localhost'
        },
        {
          userAgent: 'Mozilla/5.0',
          ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
          description: 'Full IPv6'
        },
        {
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          ip: '192.168.1.1',
          description: 'Complex User-Agent'
        },
        {
          userAgent: 'a',
          ip: '192.168.1.1',
          description: 'Minimal User-Agent'
        },
        {
          userAgent: 'Mozilla/5.0',
          ip: '0.0.0.0',
          description: 'Special IP'
        }
      ];

      const fingerprints = new Set();

      edgeCases.forEach(context => {
        const token = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );

        expect(fingerprints.has(token.payload.fingerprint)).toBe(false);
        fingerprints.add(token.payload.fingerprint);

        const token2 = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );
        expect(token.payload.fingerprint).toBe(token2.payload.fingerprint);

        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();
      });

      expect(fingerprints.size).toBe(edgeCases.length);
    });
  });

  describe('Error Handling', () => {
    test('should handle payload validation errors', () => {
      const testCases = [
        {
          payload: null,
          expectedError: ErrorMessages[ErrorCode.INVALID_PAYLOAD]
        },
        {
          payload: {},
          expectedError: ErrorMessages[ErrorCode.EMPTY_PAYLOAD]
        },
        {
          payload: { foo: 'bar' },
          expectedError: ErrorMessages[ErrorCode.MISSING_USER_ID]
        },
        {
          payload: { userId: '' },
          expectedError: ErrorMessages[ErrorCode.INVALID_USER_ID]
        }
      ];

      testCases.forEach(({ payload, expectedError }) => {
        expect(() => tokenly.generateAccessToken(payload as any))
          .toThrow(expectedError);
      });
    });

    test('should handle device limit errors', () => {
      const userId = '123';
      const maxDevices = 2;
      const tokenly = new Tokenly({
        securityConfig: { maxDevices }
      });

      const contexts = [
        { userAgent: 'Device1', ip: '192.168.1.1' },
        { userAgent: 'Device2', ip: '192.168.1.2' },
        { userAgent: 'Device3', ip: '192.168.1.3' }
      ];

      contexts.slice(0, maxDevices).forEach(context => {
        expect(() => {
          tokenly.generateAccessToken({ userId }, undefined, context);
        }).not.toThrow();
      });

      expect(() => {
        tokenly.generateAccessToken({ userId }, undefined, contexts[2]);
      }).toThrow(ErrorMessages[ErrorCode.MAX_DEVICES_REACHED]);
    });

    describe('Context Errors', () => {
      test('should throw INVALID_CONTEXT error when context is incomplete', () => {
        expect(() => {
          tokenly.generateAccessToken(
            { userId: '123' },
            undefined,
            { userAgent: '', ip: '' }
          );
        }).toThrow('Invalid or empty context values');

        expect(() => {
          tokenly.generateAccessToken(
            { userId: '123' },
            undefined,
            { userAgent: 'test' } as any
          );
        }).toThrow('Invalid or empty context values');
      });
    });

    describe('Environment Errors', () => {
      let consoleWarnSpy: any;

      beforeEach(() => {
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      });

      afterEach(() => {
        consoleWarnSpy.mockRestore();
      });

      test('should handle missing environment variables', () => {
        const originalEnv = process.env;
        process.env = {};

        const tokenly = new Tokenly();
        expect(consoleWarnSpy).toHaveBeenCalledWith(
          '\x1b[33m%s\x1b[0m',
          expect.stringContaining('WARNING: Using auto-generated secrets')
        );

        process.env = originalEnv;
      });
    });

    describe('Token Errors', () => {
      test('should throw TOKEN_EXPIRED error explicitly', async () => {
        const shortLivedTokenly = new Tokenly({
          accessTokenExpiry: '1ms'
        });
        
        const token = shortLivedTokenly.generateAccessToken({ userId: '123' });
        
        await new Promise(resolve => setTimeout(resolve, 100));
        
        expect(() => shortLivedTokenly.verifyAccessToken(token.raw))
          .toThrow(ErrorMessages[ErrorCode.TOKEN_EXPIRED]);
      });

      test('should throw INVALID_TOKEN error for malformed tokens', () => {
        expect(() => tokenly.verifyAccessToken('malformed.token'))
          .toThrow(ErrorMessages[ErrorCode.INVALID_TOKEN]);
        
        expect(() => tokenly.verifyAccessToken('malformed'))
          .toThrow(ErrorMessages[ErrorCode.INVALID_TOKEN]);
      });
    });

    describe('Payload Validation', () => {
      const invalidPayloads = [
        {
          payload: null,
          error: ErrorCode.INVALID_PAYLOAD,
          description: 'null payload'
        },
        {
          payload: {},
          error: ErrorCode.EMPTY_PAYLOAD,
          description: 'empty payload'
        },
        {
          payload: { foo: 'bar' },
          error: ErrorCode.MISSING_USER_ID,
          description: 'missing userId'
        },
        {
          payload: { userId: '' },
          error: ErrorCode.INVALID_USER_ID,
          description: 'empty userId'
        },
        {
          payload: { userId: null },
          error: ErrorCode.INVALID_USER_ID,
          description: 'null userId'
        },
        {
          payload: { userId: 123 },
          error: ErrorCode.INVALID_USER_ID,
          description: 'non-string userId'
        }
      ];

      test.each(invalidPayloads)(
        'should throw $error for $description',
        ({ payload, error }) => {
          expect(() => tokenly.generateAccessToken(payload as any))
            .toThrow(ErrorMessages[error]);
        }
      );
    });
  });

  describe('Enhanced Features', () => {
    test('should detect tokens about to expire', () => {
      const normalToken = tokenly.generateAccessToken({ userId: '123' });
      expect(tokenly.isTokenExpiringSoon(normalToken.raw, 10)).toBe(false);

      const shortLivedTokenly = new Tokenly({
        accessTokenExpiry: '2m'
      });
      const shortLivedToken = shortLivedTokenly.generateAccessToken({ userId: '123' });
      expect(tokenly.isTokenExpiringSoon(shortLivedToken.raw, 3)).toBe(true);
    });

    test('should validate token format', () => {
      const token = tokenly.generateAccessToken({ userId: '123' });
      expect(tokenly.validateTokenFormat(token.raw)).toBe(true);
      expect(tokenly.validateTokenFormat('invalid.token')).toBe(false);
    });

    test('should generate and validate one-time tokens', () => {
      const oneTimeToken = tokenly.generateOneTimeToken('password-reset');
      expect(oneTimeToken).toBeDefined();
      expect(tokenly.validateTokenFormat(oneTimeToken)).toBe(true);
    });

    test('should get token info safely', () => {
      const token = tokenly.generateAccessToken({ userId: '123' });
      const info = tokenly.getTokenInfo(token.raw);
      
      expect(info).toBeDefined();
      expect(info?.userId).toBe('123');
      expect(info?.expiresAt).toBeInstanceOf(Date);
      expect(info?.issuedAt).toBeInstanceOf(Date);
    });

    test('should handle enhanced refresh token verification', () => {
      const token = tokenly.generateRefreshToken({ userId: '123' });
      const verified = tokenly.verifyRefreshTokenEnhanced(token.raw);
      expect(verified.payload).toHaveProperty('userId', '123');
    });
  });

  describe('Advanced Features', () => {
    test('should analyze token security', () => {
      const token = tokenly.generateAccessToken({ userId: '123' });
      const analysis = tokenly.analyzeTokenSecurity(token.raw);
      
      expect(analysis).toHaveProperty('algorithm');
      expect(analysis).toHaveProperty('strength');
      expect(['weak', 'medium', 'strong']).toContain(analysis.strength);
    });

    test('should handle token events', async () => {
      let eventData: any = null;
      
      tokenly.on('tokenRevoked', (data: any) => {
        eventData = data;
      });
      
      const token = tokenly.generateAccessToken({ userId: '123' });
      tokenly.verifyAccessToken(token.raw);
      tokenly.revokeToken(token.raw);
      
      await new Promise(resolve => setTimeout(resolve, 50));
      
      expect(eventData).toBeTruthy();
      expect(eventData.token).toBe(token.raw);
      expect(eventData.userId).toBe('123');
    });

    test('should cache token verifications', () => {
      const token = tokenly.generateAccessToken({ userId: '123' });
      
      const firstVerification = tokenly.verifyAccessToken(token.raw);
      const secondVerification = tokenly.verifyAccessToken(token.raw);
      
      expect(firstVerification).toEqual(secondVerification);
    });

    test('should handle auto rotation', async () => {
      const shortLivedTokenly = new Tokenly({
        accessTokenExpiry: '1s'
      });

      let eventData: any = null;
      shortLivedTokenly.on('tokenExpiring', (data: any) => {
        eventData = data;
      });

      const token = shortLivedTokenly.generateAccessToken({ userId: '123' });
      shortLivedTokenly.verifyAccessToken(token.raw);
      
      const interval = shortLivedTokenly.enableAutoRotation({
        checkInterval: 50,
        rotateBeforeExpiry: 2000
      });

      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(eventData).toBeTruthy();
      expect(eventData.token).toBe(token.raw);
      expect(eventData.userId).toBe('123');

      clearInterval(interval);
    });

    test('should handle auto rotation disable', async () => {
      const tokenly = new Tokenly({
        accessTokenExpiry: '1s'
      });

      const interval = tokenly.enableAutoRotation();
      tokenly.disableAutoRotation();
      
      expect(tokenly['autoRotationInterval']).toBeNull();
    });
  });

  describe('Device Limit Tests', () => {
    test('should enforce maximum device limit', () => {
      const userId = '123';
      const maxDevices = 2;
      const tokenly = new Tokenly({
        securityConfig: { maxDevices }
      });

      const contexts = [
        { userAgent: 'Device1', ip: '192.168.1.1' },
        { userAgent: 'Device2', ip: '192.168.1.2' },
        { userAgent: 'Device3', ip: '192.168.1.3' }
      ];

      contexts.slice(0, maxDevices).forEach(context => {
        expect(() => {
          tokenly.generateAccessToken({ userId }, undefined, context);
        }).not.toThrow();
      });

      expect(() => {
        tokenly.generateAccessToken({ userId }, undefined, contexts[2]);
      }).toThrow('Maximum number of devices reached');
    });

    test('should allow same device to reconnect', () => {
      const userId = '123';
      const context = { userAgent: 'TestDevice', ip: '192.168.1.1' };
      
      const token1 = tokenly.generateAccessToken({ userId }, undefined, context);
      
      expect(() => {
        tokenly.generateAccessToken({ userId }, undefined, context);
      }).not.toThrow();
    });
  });
});

describe('Tokenly Environment Variables', () => {
    const originalEnv = process.env;
    let consoleWarnSpy: any;

    beforeEach(() => {
        process.env = { ...originalEnv };
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        process.env = originalEnv;
        consoleWarnSpy.mockRestore();
    });

    test('should use environment variables when provided', () => {
        process.env.JWT_SECRET_ACCESS = 'test-access-secret';
        process.env.JWT_SECRET_REFRESH = 'test-refresh-secret';

        const tokenly = new Tokenly();

        expect(consoleWarnSpy).not.toHaveBeenCalled();
        expect(tokenly.getToken()).toBeNull();
    });

    test('should generate secure secrets when env vars are missing', () => {
        delete process.env.JWT_SECRET_ACCESS;
        delete process.env.JWT_SECRET_REFRESH;

        const tokenly = new Tokenly();

        expect(consoleWarnSpy).toHaveBeenCalledWith(
            '\x1b[33m%s\x1b[0m',
            expect.stringContaining('WARNING: Using auto-generated secrets')
        );
    });

    test('should generate different secrets for different instances', () => {
        delete process.env.JWT_SECRET_ACCESS;
        delete process.env.JWT_SECRET_REFRESH;

        const tokenly1 = new Tokenly();
        const tokenly2 = new Tokenly();

        const token1 = tokenly1.generateAccessToken({ userId: '1', role: 'user' });
        const token2 = tokenly2.generateAccessToken({ userId: '1', role: 'user' });

        expect(token1.raw).not.toBe(token2.raw);
    });

    test('should maintain consistent secrets within same instance', () => {
        delete process.env.JWT_SECRET_ACCESS;
        delete process.env.JWT_SECRET_REFRESH;
        const tokenly = new Tokenly();

        const token1 = tokenly.generateAccessToken({ userId: '1', role: 'user' });
        const token2 = tokenly.generateAccessToken({ userId: '1', role: 'user' });

        expect(() => tokenly.verifyAccessToken(token1.raw)).not.toThrow();
        expect(() => tokenly.verifyAccessToken(token2.raw)).not.toThrow();
    });

    test('should warn only once per instance when using auto-generated secrets', () => {
        delete process.env.JWT_SECRET_ACCESS;
        delete process.env.JWT_SECRET_REFRESH;

        new Tokenly();
        new Tokenly();

        expect(consoleWarnSpy).toHaveBeenCalledTimes(2);
        expect(consoleWarnSpy).toHaveBeenCalledWith(
            '\x1b[33m%s\x1b[0m',
            expect.stringContaining('Instance ID:')
        );
    });
});

describe('Environment Errors', () => {
  let consoleWarnSpy: any;

  beforeEach(() => {
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleWarnSpy.mockRestore();
  });

  test('should handle missing environment variables', () => {
    const originalEnv = process.env;
    process.env = {};

    const tokenly = new Tokenly();
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      '\x1b[33m%s\x1b[0m',
      expect.stringContaining('WARNING: Using auto-generated secrets')
    );

    process.env = originalEnv;
  });
});