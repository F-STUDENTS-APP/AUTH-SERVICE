import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { sendResponse, sendError } from '../utils/response';

export const getUserForInternal = async (req: Request, res: Response) => {
  const { id } = req.params;

  // In production, this should be protected by a service token or IP whitelist
  const user = await prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      username: true,
      name: true,
      email: true,
      isActive: true,
    },
  });

  if (!user) return sendError(res, 404, 'User not found');

  return sendResponse(res, 200, true, 'User found', user);
};
