export interface TokenlyConfig {
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
  securityConfig: {
    enableFingerprint: boolean;
    enableBlacklist: boolean;
    maxDevices: number;
  }
}

export interface TokenlyResponse {
  raw: string;
  payload: any;
}

export class Tokenly {
  constructor(options: TokenlyConfig);
  generateAccessToken(payload: { userId: string; role: string }): TokenlyResponse;
  verifyAccessToken(token: string): TokenlyResponse;
  on(event: string, callback: (data: { token: string; userId: string; expiresIn: number }) => void): void;
  enableAutoRotation(options: { checkInterval: number; rotateBeforeExpiry: number }): void;
  disableAutoRotation(): void;
} 