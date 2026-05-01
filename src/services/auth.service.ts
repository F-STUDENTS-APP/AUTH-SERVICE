import prisma from '../config/prisma';
import { LoginDto } from '../validators/auth.validator';
import { comparePassword } from './password.service';
import { generateAccessToken, generateRefreshToken } from './token.service';
import { AUTH_CONFIG } from '../config/constants';
import { Prisma } from '@prisma/client';

// Define strict type for User with Roles
type UserWithRoles = Prisma.UserGetPayload<{
  include: { userRoles: { include: { role: true } } };
}>;

export class AuthService {
  /**
   * Handle user login with transaction safety
   */
  async login(data: LoginDto, ipAddress: string, userAgent?: string) {
    const { username, password } = data;

    // 1. Find User
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
      throw { status: 401, message: 'Invalid credentials' };
    }

    if (!user.isActive) {
      throw { status: 401, message: 'Account is inactive' };
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw { status: 423, message: `Account is locked until ${user.lockedUntil.toISOString()}` };
    }

    // 2. Validate Password
    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      await this.handleFailedLogin(user, ipAddress, userAgent);
      throw { status: 401, message: 'Invalid credentials' };
    }

    // 3. Handle Successful Login (Transaction)
    return await prisma.$transaction(async (tx) => {
      // 3a. Reset login attempts & update login info
      const updatedUser = await tx.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lockedUntil: null,
          lastLoginAt: new Date(),
          lastLoginIp: ipAddress,
        },
        include: {
          userRoles: {
            include: { role: true },
          },
        },
      });

      // 3b. Generate Tokens
      const roles = updatedUser.userRoles.map((ur) => ur.role.code);
      const refreshToken = generateRefreshToken({
        id: updatedUser.id,
        username: updatedUser.username,
        roles,
      });

      // 3c. Save Refresh Token
      const storedToken = await tx.refreshToken.create({
        data: {
          userId: updatedUser.id,
          token: refreshToken,
          deviceInfo: userAgent,
          ipAddress: ipAddress,
          expiresAt: new Date(
            Date.now() + AUTH_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000
          ),
        },
      });

      // 3b. Generate Access Token with Session ID (sid)
      const payload = {
        id: updatedUser.id,
        username: updatedUser.username,
        roles,
        sid: storedToken.id, // ID dari tabel refresh_tokens sebagai session ID
        isAuthorized: false,
      };

      const accessToken = generateAccessToken(payload);

      // 3d. Create Login History (Wrap in try-catch to avoid blocking login if table is missing)
      try {
        await tx.loginHistory.create({
          data: {
            userId: updatedUser.id,
            ipAddress: ipAddress,
            userAgent: userAgent,
            status: 'SUCCESS',
          },
        });
      } catch (e) {
        console.warn('⚠️ Could not save login history, but continuing login...', e.message);
      }

      return {
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          name: updatedUser.name,
          email: updatedUser.email,
          roles,
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: AUTH_CONFIG.ACCESS_TOKEN_EXPIRY_SECONDS,
        },
      };
    });
  }

  /**
   * Handle failed login attempts (Transaction Safe)
   */
  private async handleFailedLogin(user: UserWithRoles, ipAddress: string, userAgent?: string) {
    const failedAttempts = user.failedLoginAttempts + 1;
    let lockedUntil = null;

    if (failedAttempts >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
      lockedUntil = new Date(Date.now() + AUTH_CONFIG.ACCOUNT_LOCKOUT_DURATION_MINS * 60000);
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: failedAttempts,
        lockedUntil,
      },
    });

    // 2. Create Login History (Wrap in try-catch to avoid hard error)
    try {
      await prisma.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: ipAddress,
          userAgent: userAgent,
          status: 'FAILED_INVALID_CREDENTIALS',
          failReason: 'Invalid password',
        },
      });
    } catch (e) {
      console.warn('⚠️ Could not save failed login history...', e.message);
    }
  }

  /**
   * Refresh Access Token
   */
  async refreshAuth(token: string) {
    if (!token) throw { status: 400, message: 'Refresh token is required' };

    const storedToken = await prisma.refreshToken.findUnique({
      where: { token },
      include: {
        user: {
          include: {
            userRoles: {
              include: { role: true },
            },
          },
        },
      },
    });

    if (!storedToken || storedToken.isRevoked || storedToken.expiresAt < new Date()) {
      throw { status: 401, message: 'Invalid or expired refresh token' };
    }

    const { user } = storedToken;
    const roles = user.userRoles.map((ur) => ur.role.code);
    const payload = { id: user.id, username: user.username, roles, isAuthorized: false };

    const newRefreshToken = generateRefreshToken(payload);

    // Token Rotation: Revoke old token and save new one
    let newStoredToken;
    try {
      const results = await prisma.$transaction([
        prisma.refreshToken.update({
          where: { id: storedToken.id },
          data: { isRevoked: true, revokedAt: new Date() },
        }),
        prisma.refreshToken.create({
          data: {
            userId: user.id,
            token: newRefreshToken,
            expiresAt: new Date(
              Date.now() + AUTH_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000
            ),
          },
        }),
      ]);
      newStoredToken = results[1];
    } catch (e) {
      console.warn('⚠️ Error during token rotation in DB:', e.message);
      throw { status: 500, message: 'Could not complete token rotation' };
    }

    const newAccessToken = generateAccessToken({
      ...payload,
      sid: newStoredToken.id,
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: AUTH_CONFIG.ACCESS_TOKEN_EXPIRY_SECONDS,
    };
  }

  /**
   * Logout (Revoke Token)
   */
  async logout(refreshToken: string) {
    if (refreshToken) {
      await prisma.refreshToken.updateMany({
        where: { token: refreshToken },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });
    }
  }
}

export const authService = new AuthService();
