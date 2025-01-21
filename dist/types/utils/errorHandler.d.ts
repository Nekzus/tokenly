export declare enum ErrorCode {
    INVALID_TOKEN = "INVALID_TOKEN",
    TOKEN_EXPIRED = "TOKEN_EXPIRED",
    TOKEN_REVOKED = "TOKEN_REVOKED",
    INVALID_FINGERPRINT = "INVALID_FINGERPRINT",
    MAX_DEVICES_REACHED = "MAX_DEVICES_REACHED",
    MAX_ROTATION_EXCEEDED = "MAX_ROTATION_EXCEEDED",
    INVALID_PAYLOAD = "INVALID_PAYLOAD",
    EMPTY_PAYLOAD = "EMPTY_PAYLOAD",
    MISSING_USER_ID = "MISSING_USER_ID",
    INVALID_USER_ID = "INVALID_USER_ID",
    INVALID_CONTEXT = "INVALID_CONTEXT",
    MISSING_ENV_VAR = "MISSING_ENV_VAR"
}
export declare class TokenlyError extends Error {
    code: ErrorCode;
    details?: any | undefined;
    constructor(code: ErrorCode, message: string, details?: any | undefined);
}
export declare const ErrorMessages: {
    INVALID_TOKEN: string;
    TOKEN_EXPIRED: string;
    TOKEN_REVOKED: string;
    INVALID_FINGERPRINT: string;
    MAX_DEVICES_REACHED: string;
    MAX_ROTATION_EXCEEDED: string;
    INVALID_PAYLOAD: string;
    EMPTY_PAYLOAD: string;
    MISSING_USER_ID: string;
    INVALID_USER_ID: string;
    INVALID_CONTEXT: string;
    MISSING_ENV_VAR: string;
};
export declare function throwError(code: ErrorCode, details?: any): never;
