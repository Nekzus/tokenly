import { Request, Response } from 'express';
import { Tokenly } from '../../src/tokenManager';

const tokenly = new Tokenly();

export class AuthController {
  async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;
      // Verificar credenciales...

      const context = {
        userAgent: req.headers['user-agent'] || '',
        ip: req.ip
      };

      const payload = {
        userId: 'user123',
        email,
        role: 'user'
      };

      const accessToken = tokenly.generateAccessToken(payload, undefined, context);
      const refreshToken = tokenly.generateRefreshToken(payload);

      // Configurar cookie segura
      if (refreshToken.cookieConfig) {
        res.cookie(
          refreshToken.cookieConfig.name,
          refreshToken.cookieConfig.value,
          refreshToken.cookieConfig.options
        );
      }

      res.json({
        accessToken: accessToken.raw,
        expiresAt: accessToken.expiresAt
      });
    } catch (error) {
      res.status(400).json({ message: 'Login failed' });
    }
  }

  async refresh(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies.refresh_token;
      const tokens = tokenly.rotateTokens(refreshToken);

      if (tokens.refreshToken.cookieConfig) {
        res.cookie(
          tokens.refreshToken.cookieConfig.name,
          tokens.refreshToken.cookieConfig.value,
          tokens.refreshToken.cookieConfig.options
        );
      }

      res.json({
        accessToken: tokens.accessToken.raw,
        expiresAt: tokens.accessToken.expiresAt
      });
    } catch (error) {
      res.status(401).json({ message: 'Invalid refresh token' });
    }
  }
} 