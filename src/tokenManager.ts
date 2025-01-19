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
    return crypto
      .createHash('sha256')
      .update(`${context.userAgent}${context.ip}${context.additionalData || ''}`)
      .digest('hex');
  }

  /**
   * Revoca un token específico
   */
  revokeToken(token: string): void {
    console.log('DEBUG [3]: Revocando token');
    if (!token || typeof token !== 'string') {
      throw new Error('Invalid token format');
    }
    this.revokedTokens.add(token);
    console.log('DEBUG [4]: Token revocado exitosamente');
  }

  /**
   * Verifica si un token está en la lista negra
   */
  private isTokenBlacklisted(token: string): boolean {
    return this.securityConfig.enableBlacklist && this.blacklistedTokens.has(token);
  }

  private validatePayload(payload: any): void {
    if (!payload || typeof payload !== 'object') {
      throw new Error('Payload must be an object');
    }
    
    if (!Object.prototype.hasOwnProperty.call(payload, 'userId')) {
      throw new Error('Payload must contain a userId');
    }
    
    if (typeof payload.userId !== 'string' || !payload.userId.trim()) {
      throw new Error('userId must be a non-empty string');
    }
    
    if (Object.keys(payload).length === 0) {
      throw new Error('Payload cannot be empty');
    }

    Object.entries(payload).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        throw new Error(`Payload property '${key}' cannot be null or undefined`);
      }
    });

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
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('Payload must be an object');
    }

    if (Object.keys(payload).length === 0) {
      throw new Error('Payload cannot be empty');
    }

    const userId = (payload as any).userId;

    if (userId === null || userId === undefined) {
      throw new Error('userId cannot be null or undefined');
    }

    if (typeof userId !== 'string') {
      throw new Error('userId must be a string');
    }

    if (userId.length > 1000) {
      throw new Error('userId exceeds maximum length');
    }

    if (userId.trim().length === 0) {
      throw new Error('userId cannot be empty');
    }

    try {
      const finalPayload = { ...payload };

      if (this.securityConfig.enableFingerprint && context) {
        finalPayload['fingerprint'] = this.generateFingerprint(context);
        
        if (!this.deviceTokens.has(userId)) {
          this.deviceTokens.set(userId, new Set());
        }
        const userDevices = this.deviceTokens.get(userId)!;
        
        if (userDevices.size >= this.securityConfig.maxDevices) {
          throw new Error('Maximum number of devices reached');
        }
        userDevices.add(finalPayload['fingerprint']);
      }

      const token = jwt.sign(finalPayload, this.secretAccess, {
        ...this.jwtOptions,
        ...options,
        expiresIn: this.accessTokenExpiry,
      });

      return this.decodeWithReadableDates(token);
    } catch (error) {
      throw error;
    }
  }

  /**
   * Verify an access token
   * @param token JWT token string
   * @returns Verified token response
   */
  verifyAccessToken(
    token: string,
    context?: { userAgent: string; ip: string; additionalData?: string }
  ): TokenlyResponse {
    if (!token || typeof token !== 'string') {
      throw new Error('Invalid token format');
    }

    if (this.revokedTokens.has(token)) {
      throw new Error('Token has been revoked');
    }

    try {
      const decoded = jwt.verify(token, this.secretAccess, {
        ...this.verifyOptions,
        ignoreExpiration: false,
        clockTolerance: 0
      }) as TokenlyToken;

      if (this.securityConfig.enableFingerprint && context) {
        const expectedFingerprint = this.generateFingerprint(context);
        if (decoded.fingerprint !== expectedFingerprint) {
          throw new Error('Invalid token fingerprint');
        }
      }

      return this.decodeWithReadableDates(token, decoded);
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('jwt expired');
      }
      
      if (error instanceof jwt.JsonWebTokenError) {
        throw error;
      }
      
      if (error instanceof Error) {
        throw error;
      }
      
      throw new Error('Token verification failed');
    }
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
    const finalPayload = { ...payload };
    
    // Eliminar propiedades JWT existentes
    delete finalPayload['aud'];
    delete finalPayload['iss'];
    delete finalPayload['exp'];
    delete finalPayload['iat'];

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