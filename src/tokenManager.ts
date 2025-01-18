import jwt from 'jsonwebtoken';
import { getEnvVariable } from './utils.js';

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
  };
}

interface TokenlyToken extends jwt.JwtPayload {
  iat?: number;
  exp?: number;
}

interface TokenlyResponse {
  payload: object;
  issuedAt: string;
  expiresAt: string;
  raw: string;
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
  private currentToken: string | null = null;

  /**
   * Initialize Tokenly with custom configuration
   * @param config Optional configuration for token management
   */
  constructor(config?: TokenlyConfig) {
    this.secretAccess = getEnvVariable('JWT_SECRET_ACCESS');
    this.secretRefresh = getEnvVariable('JWT_SECRET_REFRESH');
    this.accessTokenExpiry =
      config?.accessTokenExpiry || getEnvVariable('ACCESS_TOKEN_EXPIRY', '15m');
    this.refreshTokenExpiry =
      config?.refreshTokenExpiry || getEnvVariable('REFRESH_TOKEN_EXPIRY', '7d');

    // Default secure cookie configuration
    this.cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      ...config?.cookieOptions,
    };

    // Default secure JWT configuration
    this.jwtOptions = {
      algorithm: 'HS512',
      ...config?.jwtOptions,
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
    decoded: TokenlyToken,
    cookieConfig?: TokenlyOptions
  ): TokenlyResponse {
    const { _iat, _exp, ...payloadWithoutDates } = decoded;
    const result: TokenlyResponse = {
      payload: {
        ...payloadWithoutDates,
        iat: decoded.iat,
        exp: decoded.exp,
        iatISO: decoded.iat ? this.formatDate(decoded.iat) : 'N/A',
        expISO: decoded.exp ? this.formatDate(decoded.exp) : 'N/A',
      },
      issuedAt: decoded.iat ? this.formatDate(decoded.iat) : 'N/A',
      expiresAt: decoded.exp ? this.formatDate(decoded.exp) : 'N/A',
      raw: token,
    };

    if (cookieConfig) {
      result.cookieConfig = {
        name: 'refresh_token',
        value: token,
        options: {
          ...this.cookieOptions,
          ...cookieConfig,
          maxAge: decoded.exp ? (decoded.exp - Date.now() / 1000) * 1000 : undefined,
        },
      };
    }

    return result;
  }

  /**
   * Generate a new access token
   * @param payload Token payload
   * @param options Optional JWT sign options
   * @returns Token response with readable dates
   */
  generateAccessToken(payload: object, options?: jwt.SignOptions): TokenlyResponse {
    const token = jwt.sign(payload, this.secretAccess, {
      ...this.jwtOptions,
      ...options,
      expiresIn: this.accessTokenExpiry,
    });
    const decoded = jwt.decode(token) as TokenlyToken;
    return this.decodeWithReadableDates(token, decoded);
  }

  /**
   * Verify an access token
   * @param token JWT token string
   * @returns Verified token response
   */
  verifyAccessToken(token: string): TokenlyResponse {
    const decoded = jwt.verify(token, this.secretAccess, {
      algorithms: [this.jwtOptions.algorithm as jwt.Algorithm],
    }) as TokenlyToken;
    return this.decodeWithReadableDates(token, decoded);
  }

  /**
   * Generate a new refresh token with HttpOnly cookie configuration
   * @param payload Token payload
   * @param cookieOptions Optional cookie configuration
   * @returns Token response with cookie configuration
   */
  generateRefreshToken(payload: object, cookieOptions?: TokenlyOptions): TokenlyResponse {
    const token = jwt.sign(payload, this.secretRefresh, {
      ...this.jwtOptions,
      expiresIn: this.refreshTokenExpiry,
    });
    const decoded = jwt.decode(token) as TokenlyToken;
    return this.decodeWithReadableDates(token, decoded, cookieOptions);
  }

  /**
   * Verify a refresh token
   * @param token JWT token string
   * @returns Verified token response
   */
  verifyRefreshToken(token: string): TokenlyResponse {
    const decoded = jwt.verify(token, this.secretRefresh, {
      algorithms: [this.jwtOptions.algorithm as jwt.Algorithm],
    }) as TokenlyToken;
    return this.decodeWithReadableDates(token, decoded);
  }

  /**
   * Rotate access and refresh tokens
   * @param refreshToken Current refresh token
   * @param newPayload Optional new payload for the tokens
   * @returns New access and refresh tokens
   */
  rotateTokens(
    refreshToken: string,
    newPayload?: object
  ): {
    accessToken: TokenlyResponse;
    refreshToken: TokenlyResponse;
  } {
    const verified = this.verifyRefreshToken(refreshToken);

    const {
      iat: _iat,
      exp: _exp,
      nbf: _nbf,
      jti: _jti,
      iss: _iss,
      aud: _aud,
      sub: _sub,
      ...cleanPayload
    } = (newPayload || verified.payload) as TokenlyToken;

    const newAccessToken = this.generateAccessToken(cleanPayload);
    const newRefreshToken = this.generateRefreshToken(cleanPayload);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
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
}
