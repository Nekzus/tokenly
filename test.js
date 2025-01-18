import 'dotenv/config';
import { TokenManager } from './dist/index.js';

const manager = new TokenManager();

// Prueba el token access
const payload = { userId: 1, email: 'test@example.com' };
const token = manager.generateAccessToken(payload);
console.log('Token generado:', token);

const decoded = manager.verifyAccessToken(token);
console.log('Token decodificado:', decoded);

// Prueba el token refresh
const refreshToken = manager.generateRefreshToken(payload);
console.log('Token refresh generado:', refreshToken);

const decodedRefresh = manager.verifyRefreshToken(refreshToken);
console.log('Token refresh decodificado:', decodedRefresh);
