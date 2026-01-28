import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/token.service';
import { sendError } from '../utils/response';
import prisma from '../config/prisma';

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendError(res, 401, 'Unauthorized: No token provided');
  }

  const token = authHeader.split(' ')[1];
  const decoded: any = verifyAccessToken(token);

  if (!decoded) {
    return sendError(res, 401, 'Unauthorized: Invalid or expired token');
  }

  // Enforce module-based authorization unless it's the authorize endpoint itself
  const isAuthorizeEndpoint = req.path.endsWith('/authorize') && req.method === 'GET';
  if (!decoded.isAuthorized && !isAuthorizeEndpoint) {
    return sendError(
      res,
      403,
      'Forbidden: Token is not authorized. Please hit /auth/authorize first.'
    );
  }

  const user = await prisma.user.findUnique({
    where: { id: decoded.id },
    include: {
      userRoles: {
        include: {
          role: true,
        },
      },
    },
  });

  if (!user || !user.isActive) {
    return sendError(res, 401, 'Unauthorized: User not found or inactive');
  }

  (req as any).user = {
    id: user.id,
    username: user.username,
    email: user.email,
    roles: user.userRoles.map((ur: any) => ur.role.code),
  };

  next();
};

export const authorize = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) {
      return sendError(res, 401, 'Unauthorized');
    }

    const hasRole = user.roles.some((role: string) => roles.includes(role));
    if (!hasRole && !user.roles.includes('SUPERADMIN')) {
      return sendError(res, 403, 'Forbidden: You do not have permission to access this resource');
    }

    next();
  };
};
