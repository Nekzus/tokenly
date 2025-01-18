# Tokenly

Tokenly es un paquete para la gestión de tokens con soporte para tokens de
acceso y de actualización, utilizando JSON Web Tokens (JWT).

## Instalación

```bash
npm install tokenly
```

## Uso

### Configuración del Entorno

Crea un archivo `.env`:

```env
TOKEN_SECRET=your-secret-key
TOKEN_EXPIRY=3600
REFRESH_TOKEN_EXPIRY=86400
```

### Código

```typescript
import { TokenManager } from "tokenly";

const manager = new TokenManager();
const token = manager.generateToken({ userId: 123 });
console.log(manager.verifyToken(token));
```

### Scripts

- `npm run build`: Compila el código TypeScript.
- `npm test`: Ejecuta las pruebas con Vitest.
- `npm run lint`: Ejecuta BiomeJS para linting.
- `npm run format`: Formatea el código con BiomeJS.
