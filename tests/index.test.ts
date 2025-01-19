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

      // Intentar generar un token para un tercer dispositivo
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
      devices.slice(0, 2).forEach(device => 
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

        // Verificar que el fingerprint existe
        expect(token.payload.fingerprint).toBeDefined();
        
        // Almacenar para comparaciones
        const key = `${context.userAgent}:${context.ip}`;
        tokensMap.set(key, token);
        fingerprints.add(token.payload.fingerprint);
      });

      // Verificar que cada combinación única genera un fingerprint único
      expect(fingerprints.size).toBe(testCases.length);
    });

    test('should maintain consistent fingerprints for same device/IP', () => {
      const context = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      // Generar múltiples tokens con el mismo contexto
      const token1 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      const token2 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      const token3 = tokenly.generateAccessToken({ userId: '123' }, undefined, context);

      // Verificar que los fingerprints son idénticos
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

      // Verificar que el token no puede ser usado con un contexto diferente
      expect(() => {
        tokenly.verifyAccessToken(token.raw, differentContext);
      }).toThrow('Invalid token fingerprint');
    });

    test('should handle complex fingerprint scenarios', () => {
      const baseContext = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X)',
        ip: '192.168.1.1'
      };

      // Caso 1: Cambio menor en User-Agent
      const slightlyDifferentUA = {
        ...baseContext,
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4.1 like Mac OS X)'
      };

      // Caso 2: Cambio en IP pero mismo dispositivo
      const differentIP = {
        ...baseContext,
        ip: '192.168.1.2'
      };

      // Caso 3: Información adicional en el contexto
      const extendedContext = {
        ...baseContext,
        additionalData: 'some-device-id'
      };

      const token = tokenly.generateAccessToken({ userId: '123' }, undefined, baseContext);

      // Verificar que cambios menores en UA no afectan la validación
      expect(() => {
        tokenly.verifyAccessToken(token.raw, slightlyDifferentUA);
      }).toThrow('Invalid token fingerprint');

      // Verificar que cambios en IP invalidan el token
      expect(() => {
        tokenly.verifyAccessToken(token.raw, differentIP);
      }).toThrow('Invalid token fingerprint');

      // Verificar que información adicional genera un fingerprint diferente
      const extendedToken = tokenly.generateAccessToken(
        { userId: '123' },
        undefined,
        extendedContext
      );
      expect(extendedToken.payload.fingerprint).not.toBe(token.payload.fingerprint);
    });

    test('should handle fingerprint changes over time', async () => {
      const context = {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken({ userId: '123' }, undefined, context);
      
      // Verificar inmediatamente
      expect(() => {
        tokenly.verifyAccessToken(token.raw, context);
      }).not.toThrow();

      // Esperar un momento y verificar de nuevo
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(() => {
        tokenly.verifyAccessToken(token.raw, context);
      }).not.toThrow();

      // Verificar con un cambio en el contexto
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

      // Cambio solo de IP
      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...originalContext,
          ip: '192.168.1.2'
        });
      }).toThrow('Invalid token fingerprint');

      // Cambio solo de User-Agent
      expect(() => {
        tokenly.verifyAccessToken(token.raw, {
          ...originalContext,
          userAgent: 'Chrome/90.0'
        });
      }).toThrow('Invalid token fingerprint');
    });

    test('should handle invalid context values', () => {
      // Contexto vacío
      expect(() => {
        tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          { userAgent: '', ip: '' }
        );
      }).toThrow();

      // Valores null
      expect(() => {
        tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          { userAgent: null as any, ip: null as any }
        );
      }).toThrow();

      // Valores undefined
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

        // Verificar que el fingerprint se genera correctamente
        expect(token.payload.fingerprint).toBeDefined();
        expect(typeof token.payload.fingerprint).toBe('string');
        expect(token.payload.fingerprint.length).toBeGreaterThan(0);

        // Verificar que el token puede ser validado con el mismo contexto
        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();
      });
    });

    test('should handle edge cases in fingerprint generation', () => {
      const edgeCases = [
        // IP en diferentes formatos
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
        // User-Agent con información compleja
        {
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          ip: '192.168.1.1',
          description: 'Complex User-Agent'
        },
        // Casos límite de longitud
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

        // Verificar unicidad del fingerprint
        expect(fingerprints.has(token.payload.fingerprint)).toBe(false);
        fingerprints.add(token.payload.fingerprint);

        // Verificar consistencia
        const token2 = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );
        expect(token.payload.fingerprint).toBe(token2.payload.fingerprint);

        // Verificar validación
        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();
      });

      // Verificar que todos los casos generaron fingerprints únicos
      expect(fingerprints.size).toBe(edgeCases.length);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle token expiration correctly', async () => {
      const customTokenly = new Tokenly({
        accessTokenExpiry: '1ms'
      });
      
      const token = customTokenly.generateAccessToken({ userId: '123' });
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(() => customTokenly.verifyAccessToken(token.raw)).toThrow('jwt expired');
    });

    test('should handle payload validation', () => {
      const testCases = [
        {
          payload: null,
          expectedError: 'Payload must be an object'
        },
        {
          payload: {},
          expectedError: 'Payload cannot be empty'
        },
        {
          payload: { foo: 'bar' },
          expectedError: 'Payload must contain a userId'
        },
        {
          payload: { userId: null },
          expectedError: 'userId cannot be null or undefined'
        },
        {
          payload: { userId: '' },
          expectedError: 'userId cannot be empty'
        }
      ];

      testCases.forEach(({ payload, expectedError }) => {
        expect(() => tokenly.generateAccessToken(payload as any)).toThrowError(expectedError);
      });
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

    // Nuevo test para verificar la desactivación
    test('should handle auto rotation disable', async () => {
      const tokenly = new Tokenly({
        accessTokenExpiry: '1s'
      });

      const interval = tokenly.enableAutoRotation();
      tokenly.disableAutoRotation();
      
      expect(tokenly['autoRotationInterval']).toBeNull();
    });
  });

  describe('Enhanced Fingerprint Tests', () => {
    test('should verify actual fingerprint content and uniqueness', () => {
      const testCases = [
        {
          userAgent: 'TestAgent',
          ip: '192.168.1.1',
          description: 'Base case'
        },
        {
          userAgent: 'TestAgent',
          ip: '192.168.1.2',
          description: 'Same UA, different IP'
        },
        {
          userAgent: 'Chrome/90.0',
          ip: '192.168.1.1',
          description: 'Different UA, same IP'
        }
      ];

      const fingerprints = new Set();
      const tokens = new Map();

      // Generar tokens y recolectar fingerprints
      testCases.forEach(context => {
        const token = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );

        const key = `${context.userAgent}:${context.ip}`;
        tokens.set(key, token);
        fingerprints.add(token.payload.fingerprint);

        // Verificar estructura del token
        expect(token.payload).toHaveProperty('fingerprint');
        expect(typeof token.payload.fingerprint).toBe('string');
        expect(token.payload.fingerprint.length).toBeGreaterThan(0);
      });

      // Verificar unicidad de fingerprints
      expect(fingerprints.size).toBe(testCases.length);

      // Verificar que cada token solo funciona con su contexto original
      testCases.forEach(context => {
        const key = `${context.userAgent}:${context.ip}`;
        const token = tokens.get(key);

        // Debe validar con su contexto original
        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();

        // No debe validar con otros contextos
        testCases.forEach(otherContext => {
          if (otherContext.userAgent !== context.userAgent || 
              otherContext.ip !== context.ip) {
            expect(() => {
              tokenly.verifyAccessToken(token.raw, otherContext);
            }).toThrow('Invalid token fingerprint');
          }
        });
      });
    });

    test('should maintain fingerprint consistency for same context', () => {
      const context = {
        userAgent: 'TestAgent',
        ip: '192.168.1.1'
      };

      // Generar múltiples tokens con el mismo contexto
      const tokens = Array.from({ length: 3 }, () => 
        tokenly.generateAccessToken({ userId: '123' }, undefined, context)
      );

      // El fingerprint debería ser el mismo para el mismo contexto
      const fingerprints = new Set(tokens.map(t => t.payload.fingerprint));
      expect(fingerprints.size).toBe(1);
    });

    test('should detect subtle context changes', () => {
      const originalContext = {
        userAgent: 'TestAgent',
        ip: '192.168.1.1'
      };

      const token = tokenly.generateAccessToken({ userId: '123' }, undefined, originalContext);

      // Verificar que el mismo contexto funciona
      expect(() => {
        tokenly.verifyAccessToken(token.raw, originalContext);
      }).not.toThrow();

      // Cambio sutil en el contexto
      const modifiedContext = {
        ...originalContext,
        ip: '192.168.1.2'
      };

      // Generar nuevo token con contexto modificado
      const newToken = tokenly.generateAccessToken({ userId: '123' }, undefined, modifiedContext);
      
      // Verificar que los fingerprints son diferentes
      expect(token.payload.fingerprint).not.toBe(newToken.payload.fingerprint);
    });

    test('should handle special characters and edge cases', () => {
      const specialCases = [
        {
          userAgent: 'Mozilla/5.0 (特殊文字)',
          ip: '192.168.1.1'
        },
        {
          userAgent: 'Mozilla/5.0 (@#$%^&*)',
          ip: '::1'
        },
        {
          userAgent: 'Mozilla/5.0 (\n\t)',
          ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        }
      ];

      const fingerprints = new Set();

      specialCases.forEach(context => {
        const token = tokenly.generateAccessToken(
          { userId: '123' },
          undefined,
          context
        );

        fingerprints.add(token.payload.fingerprint);

        // Verificar que el token es válido con su contexto original
        expect(() => {
          tokenly.verifyAccessToken(token.raw, context);
        }).not.toThrow();
      });

      // Verificar unicidad de fingerprints
      expect(fingerprints.size).toBe(specialCases.length);
    });
  });
});