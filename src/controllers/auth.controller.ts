import { Request, Response } from 'express';
import { sendResponse, sendError } from '../utils/response';
import { loginSchema } from '../validators/auth.validator';
import { authService } from '../services/auth.service';

export const login = async (req: Request, res: Response) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return sendError(res, 400, error.details[0].message);
  }

  try {
    const ipAddress = req.ip || 'unknown';
    const userAgent = req.headers['user-agent'];
    const result = await authService.login(value, ipAddress, userAgent);

    return sendResponse(res, 200, true, 'Login successful', result);
  } catch (err: unknown) {
    const error = err as { status?: number; message?: string };
    return sendError(res, error.status || 500, error.message || 'Internal Server Error');
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  // Ambil dari x-refresh-token ATAU dari Authorization header (Bearer)
  let token = req.headers['x-refresh-token'] as string;

  if (!token && req.headers.authorization) {
    token = req.headers.authorization.split(' ')[1];
  }

  try {
    const result = await authService.refreshAuth(token);
    return sendResponse(res, 200, true, 'Token refreshed', result);
  } catch (err: unknown) {
    const error = err as { status?: number; message?: string };
    return sendError(res, error.status || 500, error.message || 'Internal Server Error');
  }
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    await authService.logout(refreshToken);
    return sendResponse(res, 200, true, 'Logout successful');
  } catch (err: unknown) {
    const error = err as { status?: number; message?: string };
    return sendError(res, error.status || 500, error.message || 'Internal Server Error');
  }
};
