declare module '@nekzus/tokenly' {
  export class Tokenly {
    constructor(options: {
      accessTokenExpiry: string;
      refreshTokenExpiry: string;
      securityConfig: {
        enableFingerprint: boolean;
        enableBlacklist: boolean;
        maxDevices: number;
      }
    });

    generateAccessToken(
      payload: { userId: string; role: string },
      options: {
        fingerprint?: string;
        deviceId?: string;
      },
      context?: Record<string, any>
    ): {
      raw: string;
      payload: any;
    };

    verifyAccessToken(
      token: string,
      options: {
        fingerprint?: string;
        deviceId?: string;
      }
    ): any;

    on(event: string, callback: (data: { token: string; userId: string; expiresIn: number }) => void): void;
    enableAutoRotation(options: { checkInterval: number; rotateBeforeExpiry: number }): void;
    disableAutoRotation(): void;
  }
} 