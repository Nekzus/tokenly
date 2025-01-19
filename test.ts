import { Tokenly } from './src/index.js';

async function ejecutarPruebas() {
  try {
    // Inicializar Tokenly con configuración básica
    const tokenly = new Tokenly({
      accessTokenExpiry: '1h',
      refreshTokenExpiry: '7d',
      securityConfig: {
        enableFingerprint: true,
        enableBlacklist: true,
        maxDevices: 5
      }
    });

    // Prueba 1: Generación de token
    console.log('Prueba 1: Generación de token');
    const payload = { 
      userId: '123',
      role: 'user'
    };

    const token = tokenly.generateAccessToken(payload);
    console.log('Token generado:', token);

    // Prueba 2: Verificación de token
    console.log('\nPrueba 2: Verificación de token');
    const verificado = tokenly.verifyAccessToken(token.raw);
    console.log('Token verificado:', verificado);

    console.log('\nPruebas completadas exitosamente');

  } catch (error) {
    console.error('Error en las pruebas:', error);
    throw error;
  }
}

// Ejecutar pruebas con mejor manejo de errores
ejecutarPruebas()
  .then(() => {
    console.log('Proceso de pruebas finalizado correctamente');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Error fatal en las pruebas:', error);
    process.exit(1);
  }); 