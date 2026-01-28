import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { sendResponse, sendError } from '../utils/response';
import { roleSchema } from '../validators/auth.validator';

export const getRoles = async (req: Request, res: Response) => {
  const offset = parseInt(req.headers['x-paging-offset'] as string) || 0;
  const limit = parseInt(req.headers['x-paging-limit'] as string) || 25;
  const search = req.headers['x-paging-search'] as string;

  const where = {
    deletedAt: null,
    ...(search && {
      OR: [
        { name: { contains: search, mode: 'insensitive' as any } },
        { code: { contains: search, mode: 'insensitive' as any } },
      ],
    }),
  };

  const [items, total] = await Promise.all([
    prisma.role.findMany({
      where,
      skip: offset,
      take: limit,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.role.count({ where }),
  ]);

  return sendResponse(res, 200, true, 'Roles retrieved', {
    items,
    pagination: {
      offset,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
};

export const createRole = async (req: Request, res: Response) => {
  const { error, value } = roleSchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const existing = await prisma.role.findUnique({ where: { code: value.code } });
  if (existing) return sendError(res, 400, 'Role code already exists');

  const role = await prisma.role.create({
    data: {
      ...value,
      createdBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 201, true, 'Role created', role);
};

export const updateRole = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { error, value } = roleSchema.validate(req.body, { allowUnknown: true });
  if (error) return sendError(res, 400, error.details[0].message);

  const role = await prisma.role.findUnique({ where: { id } });
  if (!role) return sendError(res, 404, 'Role not found');
  if (role.isSystem) return sendError(res, 403, 'System roles cannot be modified');

  const updated = await prisma.role.update({
    where: { id },
    data: {
      ...value,
      updatedBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 200, true, 'Role updated', updated);
};

export const deleteRole = async (req: Request, res: Response) => {
  const { id } = req.params;

  const role = await prisma.role.findUnique({ where: { id } });
  if (!role) return sendError(res, 404, 'Role not found');
  if (role.isSystem) return sendError(res, 403, 'System roles cannot be deleted');

  await prisma.role.update({
    where: { id },
    data: {
      deletedAt: new Date(),
      isActive: false,
      updatedBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 200, true, 'Role deleted successfully');
};
