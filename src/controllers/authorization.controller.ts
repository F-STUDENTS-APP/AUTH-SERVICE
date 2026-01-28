import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { generateAccessToken } from '../services/token.service';
import { sendResponse, sendError } from '../utils/response';

export const authorizeSession = async (req: Request, res: Response) => {
  const user = (req as any).user;

  if (!user) {
    return sendError(res, 401, 'Unauthorized');
  }

  // Fetch all modules access for user's roles
  const moduleAccess = await prisma.moduleAccess.findMany({
    where: {
      role: {
        code: {
          in: user.roles,
        },
      },
      module: {
        isActive: true,
      },
    },
    include: {
      module: true,
    },
  });

  // Group by module for easier frontend consumption
  const permissions = moduleAccess.reduce((acc: any, curr) => {
    const moduleCode = curr.module.code;
    if (!acc[moduleCode]) {
      acc[moduleCode] = {
        canView: false,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        canViewAll: false,
        canDownload: false,
        canApprove: false,
      };
    }

    acc[moduleCode].canView = acc[moduleCode].canView || curr.canView;
    acc[moduleCode].canCreate = acc[moduleCode].canCreate || curr.canCreate;
    acc[moduleCode].canUpdate = acc[moduleCode].canUpdate || curr.canUpdate;
    acc[moduleCode].canDelete = acc[moduleCode].canDelete || curr.canDelete;
    acc[moduleCode].canViewAll = acc[moduleCode].canViewAll || curr.canViewAll;
    acc[moduleCode].canDownload = acc[moduleCode].canDownload || curr.canDownload;
    acc[moduleCode].canApprove = acc[moduleCode].canApprove || curr.canApprove;

    return acc;
  }, {});

  // Generate final authorized token
  const payload = {
    id: user.id,
    username: user.username,
    roles: user.roles,
    isAuthorized: true,
  };

  const accessToken = generateAccessToken(payload);

  return sendResponse(res, 200, true, 'Sesi berhasil diotorisasi', {
    accessToken,
    permissions,
  });
};
