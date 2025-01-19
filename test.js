import { Tokenly } from '@nekzus/tokenly';
import 'dotenv/config';



// Usage example
const tokenly = new Tokenly({
  accessTokenExpiry: '1h',
  refreshTokenExpiry: '7d',
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    domain: '.yourdomain.com',
    path: '/api',
  },
  jwtOptions: {
    algorithm: 'HS512',
    issuer: 'tokenly',
    audience: 'api',
  },
  securityConfig: {
    enableFingerprint: false,
    enableBlacklist: true,
    maxDevices: 5
  }
});

// Creamos un contexto para el fingerprint
const context = {
  userAgent: 'Mozilla/5.0 (Test Browser)',
  ip: '127.0.0.1',
  additionalData: 'test-device'
};

try {
  // Generamos el access token
  const accessToken = tokenly.generateAccessToken(
    { 
      userId: '123',
      role: 'user'
    }
  );

  console.log('Access Token generado:', accessToken);

  // Generamos el refresh token
  const refreshToken = tokenly.generateRefreshToken(
    { 
      userId: '123',
      role: 'user'
    }
  );

  console.log('Refresh Token generado:', refreshToken);

  // Verificamos el access token usando el token raw
  const verifiedAccess = tokenly.verifyAccessToken(accessToken.raw);
  console.log('Access Token verificado:', verifiedAccess);

  // Verificamos el refresh token usando el token raw
  const verifiedRefresh = tokenly.verifyRefreshToken(refreshToken.raw);
  console.log('Refresh Token verificado:', verifiedRefresh);

} catch (error) {
  console.error('Error:', error.message);
}
