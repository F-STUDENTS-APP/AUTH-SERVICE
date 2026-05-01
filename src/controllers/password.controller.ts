import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { sendResponse, sendError } from '../utils/response';
import { changePasswordSchema } from '../validators/auth.validator';
import {
  hashPassword,
  comparePassword,
  validatePasswordStrength,
} from '../services/password.service';
import crypto from 'crypto';
import logger from '../config/logger';
import { RabbitMQ } from '@microservices/common';

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) return sendError(res, 400, 'Email is required');

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user)
    return sendResponse(
      res,
      200,
      true,
      'If your email is registered, you will receive a reset link'
    );

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(
    Date.now() + parseInt(process.env.PASSWORD_RESET_TOKEN_EXPIRY || '60') * 60000
  );

  await prisma.passwordResetToken.create({
    data: {
      email,
      token,
      expiresAt,
    },
  });

  // Send email with token via notification-service (using RabbitMQ)
  try {
    await RabbitMQ.publish('notifications', {
      userId: user.id,
      type: 'PASSWORD_RESET',
      title: 'Permintaan Reset Password',
      message: `Halo ${user.name}, gunakan token berikut untuk mereset password Anda: ${token}. Token ini berlaku selama 60 menit.`,
      category: 'SYSTEM',
      channels: ['EMAIL'],
    });
    logger.info(`Message published to RabbitMQ for password reset email: ${user.email}`);
  } catch (error) {
    logger.error(`Failed to publish message to RabbitMQ: ${error}`);
    // Fallback or just log it - message is now queued or lost but won't block the response
  }

  return sendResponse(res, 200, true, 'Password reset link sent to email');
};

export const resetPassword = async (req: Request, res: Response) => {
  const { token, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) return sendError(res, 400, 'Passwords do not match');
  if (!validatePasswordStrength(newPassword)) return sendError(res, 400, 'Password is too weak');

  const resetToken = await prisma.passwordResetToken.findUnique({ where: { token } });
  if (!resetToken || resetToken.isUsed || resetToken.expiresAt < new Date()) {
    return sendError(res, 400, 'Invalid or expired reset token');
  }

  const user = await prisma.user.findUnique({ where: { email: resetToken.email } });
  if (!user) return sendError(res, 404, 'User not found');

  const passwordHash = await hashPassword(newPassword);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: user.id },
      data: {
        password: passwordHash,
        mustChangePassword: false,
        passwordChangedAt: new Date(),
      },
    }),
    prisma.passwordResetToken.update({
      where: { id: resetToken.id },
      data: { isUsed: true, usedAt: new Date() },
    }),
    prisma.passwordHistory.create({
      data: { userId: user.id, passwordHash },
    }),
  ]);

  return sendResponse(res, 200, true, 'Password has been reset successfully');
};

export const changePassword = async (req: Request, res: Response) => {
  const { error, value } = changePasswordSchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const { currentPassword, newPassword } = value;
  const user = await prisma.user.findUnique({ where: { id: req.user?.id } });

  if (!user || !(await comparePassword(currentPassword, user.password))) {
    return sendError(res, 401, 'Invalid current password');
  }

  const passwordHash = await hashPassword(newPassword);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: user.id },
      data: {
        password: passwordHash,
        passwordChangedAt: new Date(),
        mustChangePassword: false,
      },
    }),
    prisma.passwordHistory.create({
      data: { userId: user.id, passwordHash },
    }),
  ]);

  return sendResponse(res, 200, true, 'Password changed successfully');
};
