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
  } catch (err: any) {
    return sendError(res, err.status || 500, err.message || 'Internal Server Error');
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  const token = req.headers['x-refresh-token'] as string;

  try {
    const result = await authService.refreshAuth(token);
    return sendResponse(res, 200, true, 'Token refreshed', result);
  } catch (err: any) {
    return sendError(res, err.status || 500, err.message || 'Internal Server Error');
  }
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  try {
    await authService.logout(refreshToken);
    return sendResponse(res, 200, true, 'Logout successful');
  } catch (err: any) {
    return sendError(res, err.status || 500, err.message || 'Internal Server Error');
  }
};
