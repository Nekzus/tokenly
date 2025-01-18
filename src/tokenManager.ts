import jwt from 'jsonwebtoken';
import { getEnvVariable } from "./utils.js";

interface DecodedToken extends jwt.JwtPayload {
    iat?: number;
    exp?: number;
}

interface ReadableToken {
    payload: object;
    issuedAt: string;
    expiresAt: string;
    raw: string;
}

export class TokenManager {
    private secretAccess: string;
    private secretRefresh: string;
    private accessTokenExpiry: string;
    private refreshTokenExpiry: string;

    constructor() {
        this.secretAccess = getEnvVariable('JWT_SECRET_ACCESS');
        this.secretRefresh = getEnvVariable('JWT_SECRET_REFRESH');
        this.accessTokenExpiry = getEnvVariable('ACCESS_TOKEN_EXPIRY', '1h');
        this.refreshTokenExpiry = getEnvVariable('REFRESH_TOKEN_EXPIRY', '7d');
    }

    private formatDate(timestamp: number): string {
        return new Date(timestamp * 1000).toLocaleString();
    }

    private decodeWithReadableDates(token: string, decoded: DecodedToken): ReadableToken {
        return {
            payload: decoded,
            issuedAt: decoded.iat ? this.formatDate(decoded.iat) : 'N/A',
            expiresAt: decoded.exp ? this.formatDate(decoded.exp) : 'N/A',
            raw: token
        };
    }

    generateAccessToken(payload: object): ReadableToken {
        const token = jwt.sign(payload, this.secretAccess, { expiresIn: this.accessTokenExpiry });
        const decoded = jwt.decode(token) as DecodedToken;
        return this.decodeWithReadableDates(token, decoded);
    }

    verifyAccessToken(token: string): ReadableToken {
        const decoded = jwt.verify(token, this.secretAccess) as DecodedToken;
        return this.decodeWithReadableDates(token, decoded);
    }

    generateRefreshToken(payload: object): ReadableToken {
        const token = jwt.sign(payload, this.secretRefresh, { expiresIn: this.refreshTokenExpiry });
        const decoded = jwt.decode(token) as DecodedToken;
        return this.decodeWithReadableDates(token, decoded);
    }

    verifyRefreshToken(token: string): ReadableToken {
        const decoded = jwt.verify(token, this.secretRefresh) as DecodedToken;
        return this.decodeWithReadableDates(token, decoded);
    }
}
