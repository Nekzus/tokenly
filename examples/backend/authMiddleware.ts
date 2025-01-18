import { NextFunction, Request, Response } from 'express';
import { Tokenly } from '../../src/tokenManager';

const tokenly = new Tokenly({
  securityConfig: {
    enableFingerprint: true,
    enableBlacklist: true,
    maxDevices: 5,
    revokeOnSecurityBreach: true
  }
});

export const authMiddleware = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const context = {
      userAgent: req.headers['user-agent'] || '',
      ip: req.ip
    };

    const verified = tokenly.verifyAccessToken(token, context);
    req.user = verified.payload;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
}; 