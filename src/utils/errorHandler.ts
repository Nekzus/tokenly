export enum ErrorCode {
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  INVALID_FINGERPRINT = 'INVALID_FINGERPRINT',
  MAX_DEVICES_REACHED = 'MAX_DEVICES_REACHED',
  MAX_ROTATION_EXCEEDED = 'MAX_ROTATION_EXCEEDED',
  
  INVALID_PAYLOAD = 'INVALID_PAYLOAD',
  EMPTY_PAYLOAD = 'EMPTY_PAYLOAD',
  MISSING_USER_ID = 'MISSING_USER_ID',
  INVALID_USER_ID = 'INVALID_USER_ID',
  
  INVALID_CONTEXT = 'INVALID_CONTEXT',

  MISSING_ENV_VAR = 'MISSING_ENV_VAR'
}

export class TokenlyError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'TokenlyError';
  }
}

export const ErrorMessages = {
  [ErrorCode.INVALID_TOKEN]: 'Invalid token format or signature',
  [ErrorCode.TOKEN_EXPIRED]: 'Token has expired',
  [ErrorCode.TOKEN_REVOKED]: 'Token has been revoked',
  [ErrorCode.INVALID_FINGERPRINT]: 'Invalid token fingerprint',
  [ErrorCode.MAX_DEVICES_REACHED]: 'Maximum number of devices reached',
  [ErrorCode.MAX_ROTATION_EXCEEDED]: 'Maximum rotation count exceeded',
  [ErrorCode.INVALID_PAYLOAD]: 'Invalid payload format',
  [ErrorCode.EMPTY_PAYLOAD]: 'Payload cannot be empty',
  [ErrorCode.MISSING_USER_ID]: 'Payload must contain a userId',
  [ErrorCode.INVALID_USER_ID]: 'Invalid userId format or value',
  [ErrorCode.INVALID_CONTEXT]: 'Invalid or incomplete context data',
  [ErrorCode.MISSING_ENV_VAR]: 'Missing required environment variable'
};

export function throwError(code: ErrorCode, details?: any): never {
  throw new TokenlyError(code, ErrorMessages[code], details);
} 