export interface TokenlyConfig {
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
  securityConfig: {
    enableFingerprint: boolean;
    enableBlacklist: boolean;
    maxDevices: number;
  }
}

export interface TokenContext {
  userAgent: string;
  ip: string;
}

export interface AccessToken {
  raw: string;
  payload: {
    userId: string;
    role: string;
    [key: string]: any;
  };
}

export type Headers = Record<string, string | string[] | undefined>;

export interface InvalidFingerprintEvent {
  type: 'invalid_fingerprint';
  userId: string;
  token: string;
  context: {
    expectedFingerprint: string;
    receivedFingerprint: string;
    ip: string;
    userAgent: string;
    timestamp: string;
  };
}

export interface MaxDevicesEvent {
  type: 'max_devices_reached';
  userId: string;
  context: {
    currentDevices: number;
    maxAllowed: number;
    ip: string;
    userAgent: string;
    timestamp: string;
  };
}