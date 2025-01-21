// Configuración principal
export interface TokenlyConfig {
  accessTokenExpiry?: string;
  refreshTokenExpiry?: string;
  securityConfig?: SecurityConfig;
  rotationConfig?: RotationConfig;
  cookieConfig?: CookieConfig;
}

// Configuraciones específicas
export interface SecurityConfig {
  enableFingerprint: boolean;
  enableBlacklist: boolean;
  maxDevices: number;
  revokeOnSecurityBreach?: boolean;
}

export interface RotationConfig {
  checkInterval?: number;
  rotateBeforeExpiry?: number;
  maxRotationCount?: number;
}

export interface CookieConfig {
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
}

// Respuesta de token
export interface TokenlyResponse {
  raw: string;
  payload: {
    userId: string;
    [key: string]: any;
  };
  cookieConfig?: {
    name: string;
    value: string;
    options: CookieConfig;
  };
}

// Eventos
export interface TokenRevokedEvent {
  token: string;
  userId: string;
  timestamp: number;
}

export interface TokenExpiringEvent {
  token: string;
  userId: string;
  expiresIn: number;
}

export interface InvalidFingerprintEvent {
  token: string;
  expectedFingerprint: string;
  receivedFingerprint: string;
}

export interface MaxDevicesEvent {
  userId: string;
  currentDevices: number;
  maxDevices: number;
}

// Tipos internos (no exportados en index.ts)
interface TokenlyToken {
  iat: number;
  exp: number;
  [key: string]: any;
}

interface TokenContext {
  userAgent: string;
  ip: string;
}

interface Headers {
  [key: string]: string | string[] | undefined;
}

interface TokenSecurityAnalysis {
  algorithm: string;
  hasFingerprint: boolean;
  expirationTime: Date;
  issuedAt: Date;
  timeUntilExpiry: number;
  strength: 'weak' | 'medium' | 'strong';
}