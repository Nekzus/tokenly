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
export declare class Tokenly {
    private secretAccess;
    private secretRefresh;
    private accessTokenExpiry;
    private refreshTokenExpiry;
    private cookieOptions;
    private jwtOptions;
    private verifyOptions;
    private currentToken;
    private blacklistedTokens;
    private rotationConfig;
    private securityConfig;
    private deviceTokens;
    private rotationCounts;
    private revokedTokens;
    private tokenCache;
    private eventListeners;
    private autoRotationInterval;
    private fingerprintCache;
    private readonly instanceSalt;
    /**
     * Initialize Tokenly with custom configuration
     * @param config Optional configuration for token management
     */
    constructor(config?: TokenlyConfig);
    /**
     * Format Unix timestamp to ISO date string
     * @param timestamp Unix timestamp in seconds
     * @returns ISO 8601 formatted date string
     */
    private formatDate;
    /**
     * Decode token and add readable dates
     * @param token JWT token string
     * @param decoded Decoded token payload
     * @param cookieConfig Optional cookie configuration
     * @returns Formatted token response
     */
    private decodeWithReadableDates;
    /**
     * Genera una huella digital del dispositivo/navegador
     */
    private generateFingerprint;
    /**
     * Revoca un token específico
     */
    revokeToken(token: string): void;
    /**
     * Verifica si un token está en la lista negra
     */
    private isTokenBlacklisted;
    private validatePayload;
    /**
     * Generate a new access token
     * @param payload Token payload
     * @param options Optional JWT sign options
     * @returns Token response with readable dates
     */
    generateAccessToken(payload: object, options?: jwt.SignOptions, context?: {
        userAgent: string;
        ip: string;
    }): TokenlyResponse;
    /**
     * Verify an access token
     * @param token JWT token string
     * @returns Verified token response
     */
    verifyAccessToken(token: string, context?: {
        userAgent: string;
        ip: string;
        additionalData?: string;
    }): TokenlyResponse;
    /**
     * Generate a new refresh token with HttpOnly cookie configuration
     * @param payload Token payload
     * @param cookieOptions Optional cookie configuration
     * @returns Token response with cookie configuration
     */
    generateRefreshToken(payload: object, cookieOptions?: TokenlyOptions): TokenlyResponse;
    /**
     * Verify a refresh token
     * @param token JWT token string
     * @returns Verified token response
     */
    verifyRefreshToken(token: string): TokenlyResponse;
    /**
     * Rotate access and refresh tokens
     * @param refreshToken Current refresh token
     * @param newPayload Optional new payload for the tokens
     * @returns New access and refresh tokens
     */
    rotateTokens(refreshToken: string): {
        accessToken: TokenlyResponse;
        refreshToken: TokenlyResponse;
    };
    /**
     * Store a token
     * @param token Token string to store
     */
    setToken(token: string): void;
    /**
     * Retrieve the stored token
     * @returns The stored token or null if none exists
     */
    getToken(): string | null;
    /**
     * Clear the stored token
     */
    clearToken(): void;
    /**
     * Helper para verificar si un token está próximo a expirar
     * @param token Token a verificar
     * @param thresholdMinutes Minutos antes de la expiración para considerar como "próximo a expirar"
     */
    isTokenExpiringSoon(token: string, thresholdMinutes?: number): boolean;
    /**
     * Helper para obtener información del token de forma segura
     * @param token Token a decodificar
     */
    getTokenInfo(token: string): TokenInfo | null;
    /**
     * Validar un token sin verificar la firma (útil para pre-validaciones)
     * @param token Token a validar
     */
    validateTokenFormat(token: string): boolean;
    /**
     * Generar un token temporal de un solo uso
     * @param purpose Propósito del token
     * @param expiresIn Tiempo de expiración
     */
    generateOneTimeToken(purpose: string, expiresIn?: string): string;
    /**
     * Validar un refresh token con verificaciones adicionales de seguridad
     */
    verifyRefreshTokenEnhanced(token: string): TokenlyResponse;
    on(event: string, callback: Function): void;
    private emit;
    private cacheToken;
    analyzeTokenSecurity(token: string): TokenSecurityAnalysis;
    private calculateTokenStrength;
    enableAutoRotation(options?: AutoRotationOptions): NodeJS.Timeout;
    disableAutoRotation(): void;
    private checkTokensExpiration;
    enableAutoCleanup(interval?: number): void;
    private handleDeviceStorage;
}
interface TokenInfo {
    userId: string;
    expiresAt: Date;
    issuedAt: Date;
    fingerprint?: string;
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
export {};
