import { Request, Response, NextFunction } from 'express';
import { sendError } from '../utils/response';

export const internalAuth = (req: Request, res: Response, next: NextFunction) => {
  const internalKey = req.headers['x-internal-key'];
  const expectedKey = process.env.INTERNAL_API_KEY;

  if (!expectedKey) {
    return sendError(res, 500, 'Internal API Key is not configured');
  }

  if (!internalKey || internalKey !== expectedKey) {
    return sendError(res, 401, 'Unauthorized internal access');
  }

  next();
};
