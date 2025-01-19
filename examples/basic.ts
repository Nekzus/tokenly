import { Tokenly } from '../src';

const tokenly = new Tokenly({
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 3
  }
});

// Generar token
const token = tokenly.generateAccessToken({ 
  userId: '123',
  role: 'user'
});

// Verificar token
try {
  const verified = tokenly.verifyAccessToken(token.raw);
  console.log('Token verificado:', verified);
} catch (error) {
  console.error('Error al verificar token:', error);
}

// Escuchar eventos
tokenly.on('tokenExpiring', (data) => {
  console.log('Token próximo a expirar:', data);
});

// Habilitar auto-rotación
const interval = tokenly.enableAutoRotation({
  checkInterval: 1000,
  rotateBeforeExpiry: 5000
});

// Limpiar al finalizar
setTimeout(() => {
  tokenly.disableAutoRotation();
}, 10000); 