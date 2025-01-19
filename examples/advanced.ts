import { Tokenly } from '../src';

const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 3,
    revokeOnSecurityBreach: true
  },
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
});

// Manejo de eventos
tokenly.on('tokenRevoked', (data) => {
  console.log('Token revocado:', data);
});

tokenly.on('tokenExpiring', (data) => {
  console.log('Token expirando:', data);
});

tokenly.on('maxDevicesReached', (data) => {
  console.log('Límite de dispositivos alcanzado:', data);
});

// Ejemplo con múltiples dispositivos
const devices = [
  { userAgent: 'Mozilla/5.0', ip: '192.168.1.1' },
  { userAgent: 'Chrome/90.0', ip: '192.168.1.2' },
  { userAgent: 'Safari/14.0', ip: '192.168.1.3' }
];

devices.forEach((device, index) => {
  try {
    const token = tokenly.generateAccessToken(
      { userId: '123', deviceId: index },
      undefined,
      device
    );
    console.log(`Token generado para dispositivo ${index}:`, token);
  } catch (error) {
    console.error(`Error al generar token para dispositivo ${index}:`, error);
  }
}); 