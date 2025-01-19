import crypto from 'crypto';
import jwt from 'jsonwebtoken';

interface TokenlyOptions {
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
}

interface TokenlyConfig {
  accessTokenExpiry?: string;
  refreshTokenExpiry?: string;
  cookieOptions?: TokenlyOptions;
  jwtOptions?: {
    algorithm?: jwt.Algorithm;
    audience?: string | string[];
    issuer?: string;
    jwtid?: string;
    subject?: string;
    notBefore?: string | number;
    maxAge?: string | number;
  };
  rotationConfig?: {
    enableAutoRotation?: boolean;
    rotationInterval?: number;
    maxRotationCount?: number;
  };
  securityConfig?: {
    enableFingerprint?: boolean;
    enableBlacklist?: boolean;
    maxDevices?: number;
    revokeOnSecurityBreach?: boolean;
  };
}

interface TokenlyToken {
  iat: number;
  exp: number;
  [key: string]: any;
}

interface TokenlyResponse {
  raw: string;
  payload: {
    [key: string]: any;
    iat?: Date;
    exp?: Date;
  };
  cookieConfig?: {
    name: string;
    value: string;
    options: TokenlyOptions;
  };
}

/**
 * Tokenly - A secure JWT token manager with HttpOnly cookie support
 * Implements best security practices for JWT token handling in modern web applications
 */
export class Tokenly {
  private secretAccess: string;
  private secretRefresh: string;
  private accessTokenExpiry: string;
  private refreshTokenExpiry: string;
  private cookieOptions: TokenlyOptions;
  private jwtOptions: jwt.SignOptions;
  private verifyOptions: jwt.VerifyOptions;
  private currentToken: string | null = null;
  private blacklistedTokens: Set<string> = new Set();
  private rotationConfig: Required<NonNullable<TokenlyConfig['rotationConfig']>>;
  private securityConfig: Required<NonNullable<TokenlyConfig['securityConfig']>>;
  private deviceTokens: Map<string, Set<string>> = new Map();
  private rotationCounts: Map<string, number> = new Map();
  private revokedTokens: Set<string> = new Set();
  private tokenCache: Map<string, TokenlyResponse>;
  private eventListeners: Map<string, Function[]>;
  private autoRotationInterval: NodeJS.Timeout | null = null;

  /**
   * Initialize Tokenly with custom configuration
   * @param config Optional configuration for token management
   */
  constructor(config?: TokenlyConfig) {
    this.secretAccess = process.env.JWT_SECRET_ACCESS || 'default-secret-access';
    this.secretRefresh = process.env.JWT_SECRET_REFRESH || 'default-secret-refresh';
    this.accessTokenExpiry = config?.accessTokenExpiry || process.env.ACCESS_TOKEN_EXPIRY || '15m';
    this.refreshTokenExpiry = config?.refreshTokenExpiry || process.env.REFRESH_TOKEN_EXPIRY || '7d';

    // Default secure cookie configuration
    this.cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      ...config?.cookieOptions,
    };

    // Default secure JWT configuration
    this.jwtOptions = {
      algorithm: 'HS512',
      issuer: 'tokenly-auth',
      audience: 'tokenly-client',
      ...config?.jwtOptions,
    };

    // Configuración JWT para verificación
    this.verifyOptions = {
      algorithms: [this.jwtOptions.algorithm as jwt.Algorithm],
      issuer: this.jwtOptions.issuer,
      audience: this.jwtOptions.audience,
      clockTolerance: 30, // 30 segundos de tolerancia solo para verificación
    };

    // Configuración de rotación automática
    this.rotationConfig = {
      enableAutoRotation: true,
      rotationInterval: 60, // 60 minutos
      maxRotationCount: 100,
      ...config?.rotationConfig,
    };

    // Configuración de seguridad
    this.securityConfig = {
      enableFingerprint: true,
      enableBlacklist: true,
      maxDevices: 5,
      revokeOnSecurityBreach: true,
      ...config?.securityConfig,
    };

    this.eventListeners = new Map();
    this.tokenCache = new Map();
  }

  /**
   * Format Unix timestamp to ISO date string
   * @param timestamp Unix timestamp in seconds
   * @returns ISO 8601 formatted date string
   */
  private formatDate(timestamp: number): string {
    return new Date(timestamp * 1000).toISOString();
  }

  /**
   * Decode token and add readable dates
   * @param token JWT token string
   * @param decoded Decoded token payload
   * @param cookieConfig Optional cookie configuration
   * @returns Formatted token response
   */
  private decodeWithReadableDates(
    token: string,
    decoded?: any
  ): TokenlyResponse {
    if (!decoded) {
      decoded = jwt.decode(token) as TokenlyToken;
    }

    const { iat, exp, ...payloadWithoutDates } = decoded;
    
    const result: TokenlyResponse = {
      raw: token,
      payload: {
        ...payloadWithoutDates,
        iat: iat ? new Date(iat * 1000) : undefined,
        exp: exp ? new Date(exp * 1000) : undefined,
      }
    };

    return result;
  }

  /**
   * Genera una huella digital del dispositivo/navegador
   */
  private generateFingerprint(context: { userAgent: string; ip: string; additionalData?: string }): string {
    if (!context.userAgent || !context.ip) {
      throw new Error('Invalid context for fingerprint generation');
    }

    // Normalizar valores
    const normalizedUA = context.userAgent.trim();
    const normalizedIP = context.ip.trim();

    // Usar un separador único para evitar colisiones
    const fingerprintData = JSON.stringify({
      ua: normalizedUA,
      ip: normalizedIP,
      additional: context.additionalData || ''
    });

    return crypto
      .createHash('sha256')
      .update(fingerprintData)
      .digest('hex');
  }

  /**
   * Revoca un token específico
   */
  public revokeToken(token: string): void {
    if (!token) return;
    
    try {
      const decoded = jwt.decode(token) as jwt.JwtPayload;
      this.revokedTokens.add(token);
      
      this.emit('tokenRevoked', {
        token,
        userId: decoded?.userId,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Error al revocar token:', error);
    }
  }

  /**
   * Verifica si un token está en la lista negra
   */
  private isTokenBlacklisted(token: string): boolean {
    return this.securityConfig.enableBlacklist && this.blacklistedTokens.has(token);
  }

  private validatePayload(payload: any): void {
    // Validar que payload sea un objeto
    if (payload === null || typeof payload !== 'object') {
      throw new Error('Payload must be an object');
    }
    
    // Validar que no esté vacío
    if (Object.keys(payload).length === 0) {
      throw new Error('Payload cannot be empty');
    }

    // Validar que tenga userId
    if (!Object.prototype.hasOwnProperty.call(payload, 'userId')) {
      throw new Error('Payload must contain a userId');
    }
    
    // Validar que userId no sea null o undefined
    if (payload.userId === null || payload.userId === undefined) {
      throw new Error('userId cannot be null or undefined');
    }

    // Validar que userId no esté vacío
    if (typeof payload.userId !== 'string' || !payload.userId.trim()) {
      throw new Error('userId cannot be empty');
    }

    // Validar que ninguna propiedad sea null o undefined
    Object.entries(payload).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        throw new Error(`Payload property '${key}' cannot be null or undefined`);
      }
    });

    // Validar tamaño del payload
    const payloadSize = JSON.stringify(payload).length;
    if (payloadSize > 8192) {
      throw new Error('Payload size exceeds maximum allowed size');
    }
  }

  /**
   * Generate a new access token
   * @param payload Token payload
   * @param options Optional JWT sign options
   * @returns Token response with readable dates
   */
  generateAccessToken(
    payload: object,
    options?: jwt.SignOptions,
    context?: { userAgent: string; ip: string; additionalData?: string }
  ): TokenlyResponse {
    this.validatePayload(payload);
    const finalPayload: { [key: string]: any } = { ...payload };

    if (this.securityConfig.enableFingerprint && context) {
      const fingerprint = this.generateFingerprint(context);
      const userId = (payload as any).userId;
      
      if (!this.deviceTokens.has(userId)) {
        this.deviceTokens.set(userId, new Set());
      }
      
      const userDevices = this.deviceTokens.get(userId)!;
      if (userDevices.size >= this.securityConfig.maxDevices && !userDevices.has(fingerprint)) {
        throw new Error('Maximum number of devices reached');
      }
      
      userDevices.add(fingerprint);
      finalPayload.fingerprint = fingerprint;
    }

    const token = jwt.sign(finalPayload, this.secretAccess, {
      ...this.jwtOptions,
      ...options,
      expiresIn: this.accessTokenExpiry,
    });

    const response = this.decodeWithReadableDates(token);
    this.tokenCache.set(token, response);
    return response;
  }

  /**
   * Verify an access token
   * @param token JWT token string
   * @returns Verified token response
   */
  public verifyAccessToken(
    token: string,
    context?: { userAgent: string; ip: string; additionalData?: string }
  ): TokenlyResponse {
    if (this.revokedTokens.has(token)) {
      throw new Error('Token has been revoked');
    }

    const verified = jwt.verify(token, this.secretAccess, {
      ...this.verifyOptions,
      ignoreExpiration: false,
      clockTolerance: 0
    }) as TokenlyToken;

    if (this.securityConfig.enableFingerprint && context) {
      const currentFingerprint = this.generateFingerprint(context);
      if (verified.fingerprint && verified.fingerprint !== currentFingerprint) {
        throw new Error('Invalid token fingerprint');
      }
    }

    const response = this.decodeWithReadableDates(token, verified);
    this.tokenCache.set(token, response);
    return response;
  }

  /**
   * Generate a new refresh token with HttpOnly cookie configuration
   * @param payload Token payload
   * @param cookieOptions Optional cookie configuration
   * @returns Token response with cookie configuration
   */
  generateRefreshToken(
    payload: object,
    cookieOptions?: TokenlyOptions
  ): TokenlyResponse {
    this.validatePayload(payload);
    const finalPayload: { [key: string]: any } = { ...payload };
    
    // Eliminar propiedades JWT existentes
    delete (finalPayload as any).aud;
    delete (finalPayload as any).iss;
    delete (finalPayload as any).exp;
    delete (finalPayload as any).iat;

    const token = jwt.sign(finalPayload, this.secretRefresh, {
      ...this.jwtOptions,
      expiresIn: this.refreshTokenExpiry,
    });

    const response = this.decodeWithReadableDates(token);
    response.cookieConfig = {
      name: 'refresh_token',
      value: token,
      options: {
        ...this.cookieOptions,
        ...cookieOptions,
      }
    };

    return response;
  }

  /**
   * Verify a refresh token
   * @param token JWT token string
   * @returns Verified token response
   */
  verifyRefreshToken(token: string): TokenlyResponse {
    const decoded = jwt.verify(token, this.secretRefresh, this.verifyOptions) as TokenlyToken;
    return this.decodeWithReadableDates(token, decoded);
  }

  /**
   * Rotate access and refresh tokens
   * @param refreshToken Current refresh token
   * @param newPayload Optional new payload for the tokens
   * @returns New access and refresh tokens
   */
  rotateTokens(refreshToken: string): {
    accessToken: TokenlyResponse;
    refreshToken: TokenlyResponse;
  } {
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new Error('Invalid refresh token format');
    }

    const verified = this.verifyRefreshToken(refreshToken);
    const { iat, exp, aud, iss, ...payload } = verified.payload;

    // Verificar límite de rotaciones
    const tokenId = refreshToken;
    const currentCount = this.rotationCounts.get(tokenId) || 0;
    
    if (currentCount >= (this.rotationConfig.maxRotationCount || 2)) {
      throw new Error('Maximum rotation count exceeded');
    }
    
    this.rotationCounts.set(tokenId, currentCount + 1);

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload)
    };
  }

  /**
   * Store a token
   * @param token Token string to store
   */
  setToken(token: string): void {
    this.currentToken = token;
  }

  /**
   * Retrieve the stored token
   * @returns The stored token or null if none exists
   */
  getToken(): string | null {
    return this.currentToken;
  }

  /**
   * Clear the stored token
   */
  clearToken(): void {
    this.currentToken = null;
  }

  /**
   * Helper para verificar si un token está próximo a expirar
   * @param token Token a verificar
   * @param thresholdMinutes Minutos antes de la expiración para considerar como "próximo a expirar"
   */
  public isTokenExpiringSoon(token: string, thresholdMinutes: number = 5): boolean {
    try {
      const decoded = jwt.decode(token) as jwt.JwtPayload;
      if (!decoded || !decoded.exp) return false;

      const expirationTime = decoded.exp * 1000;
      const currentTime = Date.now();
      const timeUntilExpiry = expirationTime - currentTime;
      
      return timeUntilExpiry < (thresholdMinutes * 60 * 1000);
    } catch {
      return false;
    }
  }

  /**
   * Helper para obtener información del token de forma segura
   * @param token Token a decodificar
   */
  public getTokenInfo(token: string): TokenInfo | null {
    try {
      const decoded = jwt.decode(token) as jwt.JwtPayload;
      if (!decoded) return null;

      return {
        userId: decoded.userId as string,
        expiresAt: new Date(decoded.exp! * 1000),
        issuedAt: new Date(decoded.iat! * 1000),
        fingerprint: decoded.fingerprint as string | undefined
      };
    } catch {
      return null;
    }
  }

  /**
   * Validar un token sin verificar la firma (útil para pre-validaciones)
   * @param token Token a validar
   */
  public validateTokenFormat(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;

      return parts.every(part => {
        try {
          Buffer.from(part, 'base64').toString();
          return true;
        } catch {
          return false;
        }
      });
    } catch {
      return false;
    }
  }

  /**
   * Generar un token temporal de un solo uso
   * @param purpose Propósito del token
   * @param expiresIn Tiempo de expiración
   */
  public generateOneTimeToken(purpose: string, expiresIn: string = '5m'): string {
    const payload = {
      purpose,
      nonce: crypto.randomBytes(16).toString('hex'),
      iat: Math.floor(Date.now() / 1000)
    };

    return jwt.sign(payload, this.secretAccess, { expiresIn });
  }

  /**
   * Mejorar la seguridad de las cookies con flags adicionales
   */
  private getEnhancedCookieOptions(): CookieOptions {
    return {
      ...this.cookieOptions,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      path: '/',
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      maxAge: 7 * 24 * 60 * 60 * 1000
    };
  }

  /**
   * Validar un refresh token con verificaciones adicionales de seguridad
   */
  public verifyRefreshTokenEnhanced(token: string): TokenlyResponse {
    if (!this.validateTokenFormat(token)) {
      throw new Error('Invalid token format');
    }

    const verified = this.verifyRefreshToken(token);
    
    if (this.isTokenExpiringSoon(token, 60)) {
      throw new Error('Refresh token is about to expire');
    }

    return verified;
  }

  // Sistema de eventos
  public on(event: string, callback: Function): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)?.push(callback);
  }

  private emit(event: string, data: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners?.length) {
      listeners.forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          // Silent error handling for callbacks
        }
      });
    }
  }

  // Sistema de caché con auto-limpieza
  private cacheToken(key: string, value: TokenlyResponse): void {
    this.tokenCache.set(key, value);
    
    // Auto-limpieza después de 5 minutos
    setTimeout(() => {
      this.tokenCache.delete(key);
    }, 5 * 60 * 1000);
  }

  // Análisis de seguridad del token
  public analyzeTokenSecurity(token: string): TokenSecurityAnalysis {
    const decoded = jwt.decode(token, { complete: true }) as { 
      header: { alg: string }, 
      payload: TokenlyToken & { fingerprint?: string } 
    };
    if (!decoded) throw new Error('Invalid token');

    return {
      algorithm: decoded.header.alg,
      hasFingerprint: !!decoded.payload.fingerprint,
      expirationTime: new Date(decoded.payload.exp * 1000),
      issuedAt: new Date(decoded.payload.iat * 1000),
      timeUntilExpiry: (decoded.payload.exp * 1000) - Date.now(),
      strength: this.calculateTokenStrength(decoded)
    };
  }

  // Calcular la fortaleza del token
  private calculateTokenStrength(decodedToken: any): 'weak' | 'medium' | 'strong' {
    let score = 0;
    
    // Verificar algoritmo
    if (decodedToken.header.alg === 'HS512') score += 2;
    else if (decodedToken.header.alg === 'HS256') score += 1;
    
    // Verificar fingerprint
    if (decodedToken.payload.fingerprint) score += 2;
    
    // Verificar tiempo de expiración
    const timeUntilExpiry = (decodedToken.payload.exp * 1000) - Date.now();
    if (timeUntilExpiry < 15 * 60 * 1000) score += 1; // < 15 minutos
    else if (timeUntilExpiry < 60 * 60 * 1000) score += 2; // < 1 hora
    
    return score <= 2 ? 'weak' : score <= 4 ? 'medium' : 'strong';
  }

  // Rotación automática de tokens
  public enableAutoRotation(options: AutoRotationOptions = {}): NodeJS.Timeout {
    console.log('Enabling auto rotation...');
    const {
      checkInterval = 50,
      rotateBeforeExpiry = 1000
    } = options;

    if (this.autoRotationInterval) {
      clearInterval(this.autoRotationInterval);
    }

    // Ejecutar verificación inmediata
    this.checkTokensExpiration(rotateBeforeExpiry);

    // Configurar nuevo intervalo
    this.autoRotationInterval = setInterval(() => {
      this.checkTokensExpiration(rotateBeforeExpiry);
    }, checkInterval);

    return this.autoRotationInterval;
  }

  // Método para detener la auto-rotación
  public disableAutoRotation(): void {
    if (this.autoRotationInterval) {
      clearInterval(this.autoRotationInterval);
      this.autoRotationInterval = null;
    }
  }

  private checkTokensExpiration(rotateBeforeExpiry: number): void {
    Array.from(this.tokenCache.entries()).forEach(([token, _]) => {
      try {
        const decoded = jwt.decode(token) as jwt.JwtPayload;
        if (decoded?.exp) {
          const timeUntilExpiry = (decoded.exp * 1000) - Date.now();
          if (timeUntilExpiry < rotateBeforeExpiry) {
            this.emit('tokenExpiring', {
              token,
              userId: decoded.userId,
              expiresIn: timeUntilExpiry
            });
          }
        }
      } catch (error) {
        // Silent error handling for token checks
      }
    });
  }

  // Limpieza automática de tokens revocados
  public enableAutoCleanup(interval: number = 3600000): void { // 1 hora por defecto
    setInterval(() => {
      const now = Date.now();
      this.revokedTokens.forEach(token => {
        try {
          const decoded = jwt.decode(token) as jwt.JwtPayload;
          if (decoded && decoded.exp && decoded.exp * 1000 < now) {
            this.revokedTokens.delete(token);
          }
        } catch {
          // Token inválido, eliminarlo
          this.revokedTokens.delete(token);
        }
      });
    }, interval);
  }

  private findTokenByFingerprint(fingerprint: string): string | null {
    for (const [, devices] of this.deviceTokens.entries()) {
      if (devices.has(fingerprint)) {
        return this.getToken();
      }
    }
    return null;
  }

  private async validateDeviceLimit(userId: string, fingerprint: string): Promise<void> {
    if (!this.deviceTokens.has(userId)) {
      this.deviceTokens.set(userId, new Set());
    }

    const userDevices = this.deviceTokens.get(userId)!;
    
    if (userDevices.size >= this.securityConfig.maxDevices && !userDevices.has(fingerprint)) {
      this.emit('maxDevicesReached', {
        userId,
        currentDevices: Array.from(userDevices),
        maxDevices: this.securityConfig.maxDevices
      });
      throw new Error('Maximum number of devices reached');
    }
    
    userDevices.add(fingerprint);
  }
}

// Tipos adicionales
interface TokenInfo {
  userId: string;
  expiresAt: Date;
  issuedAt: Date;
  fingerprint?: string;
}

interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  expires?: Date;
  maxAge?: number;
}

interface TokenSecurityAnalysis {
  algorithm: string;
  hasFingerprint: boolean;
  expirationTime: Date;
  issuedAt: Date;
  timeUntilExpiry: number;
  strength: 'weak' | 'medium' | 'strong';
}

interface AutoRotationOptions {
  checkInterval?: number;
  rotateBeforeExpiry?: number;
}