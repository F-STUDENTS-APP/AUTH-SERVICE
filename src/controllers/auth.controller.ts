import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { comparePassword } from '../services/password.service';
import { generateAccessToken, generateRefreshToken } from '../services/token.service';
import { sendResponse, sendError } from '../utils/response';
import { loginSchema } from '../validators/auth.validator';
import logger from '../config/logger';

export const login = async (req: Request, res: Response) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return sendError(res, 400, error.details[0].message);
  }

  const { username, password, rememberMe } = value;

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ username }, { email: username }],
    },
    include: {
      userRoles: {
        include: {
          role: true,
        },
      },
    },
  });

  if (!user) {
    return sendError(res, 401, 'Invalid credentials');
  }

  if (!user.isActive) {
    return sendError(res, 401, 'Account is inactive');
  }

  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return sendError(res, 423, `Account is locked until ${user.lockedUntil.toISOString()}`);
  }

  const isPasswordValid = await comparePassword(password, user.password);

  if (!isPasswordValid) {
    const failedAttempts = user.failedLoginAttempts + 1;
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
    let lockedUntil = null;

    if (failedAttempts >= maxAttempts) {
      lockedUntil = new Date(
        Date.now() + parseInt(process.env.ACCOUNT_LOCKOUT_DURATION || '30') * 60000
      );
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: failedAttempts,
        lockedUntil,
      },
    });

    await prisma.loginHistory.create({
      data: {
        userId: user.id,
        ipAddress: req.ip || 'unknown',
        userAgent: req.headers['user-agent'],
        status: 'FAILED_INVALID_CREDENTIALS',
        failReason: 'Invalid password',
      },
    });

    return sendError(res, 401, 'Invalid credentials');
  }

  // Reset failed attempts on success
  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: new Date(),
      lastLoginIp: req.ip || 'unknown',
    },
  });

  const roles = user.userRoles.map((ur: any) => ur.role.code);
  const payload = { id: user.id, username: user.username, roles, isAuthorized: false };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  // Save refresh token
  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      token: refreshToken,
      deviceInfo: req.headers['user-agent'],
      ipAddress: req.ip || 'unknown',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });

  await prisma.loginHistory.create({
    data: {
      userId: user.id,
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'],
      status: 'SUCCESS',
    },
  });

  return sendResponse(res, 200, true, 'Login successful', {
    user: {
      id: user.id,
      username: user.username,
      name: user.name,
      email: user.email,
      roles,
    },
    tokens: {
      accessToken,
      refreshToken,
      expiresIn: 900, // 15 mins
    },
  });
};

export const refreshToken = async (req: Request, res: Response) => {
  const token = req.headers['x-refresh-token'] as string;

  if (!token) {
    return sendError(res, 400, 'Refresh token is required');
  }

  const storedToken = await prisma.refreshToken.findUnique({
    where: { token },
    include: {
      user: {
        include: {
          userRoles: {
            include: {
              role: true,
            },
          },
        },
      },
    },
  });

  if (!storedToken || storedToken.isRevoked || storedToken.expiresAt < new Date()) {
    return sendError(res, 401, 'Invalid or expired refresh token');
  }

  const user = storedToken.user;
  const roles = user.userRoles.map((ur: any) => ur.role.code);
  const payload = { id: user.id, username: user.username, roles, isAuthorized: false };

  const accessToken = generateAccessToken(payload);

  return sendResponse(res, 200, true, 'Token refreshed', {
    accessToken,
    expiresIn: 900,
  });
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    await prisma.refreshToken.updateMany({
      where: { token: refreshToken },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });
  }

  return sendResponse(res, 200, true, 'Logout successful');
};
