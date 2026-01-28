import { Request, Response } from 'express';
import prisma from '../config/prisma';
import { sendResponse, sendError } from '../utils/response';
import { moduleSchema } from '../validators/auth.validator';

export const getModules = async (req: Request, res: Response) => {
  const hierarchical = req.query.hierarchical === 'true';
  const includeInactive = req.query.includeInactive === 'true';

  const where = {
    deletedAt: null,
    ...(!includeInactive && { isActive: true }),
  };

  const modules = await prisma.module.findMany({
    where,
    orderBy: { order: 'asc' },
  });

  if (hierarchical) {
    const buildHierarchy = (parentId: string | null = null): any[] => {
      return modules
        .filter((m: any) => m.parentId === parentId)
        .map((m: any) => ({
          ...m,
          children: buildHierarchy(m.id),
        }));
    };
    return sendResponse(res, 200, true, 'Modules retrieved (hierarchical)', buildHierarchy(null));
  }

  return sendResponse(res, 200, true, 'Modules retrieved', modules);
};

export const createModule = async (req: Request, res: Response) => {
  const { error, value } = moduleSchema.validate(req.body);
  if (error) return sendError(res, 400, error.details[0].message);

  const module = await prisma.module.create({
    data: {
      ...value,
      createdBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 201, true, 'Module created', module);
};

export const updateModule = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { error, value } = moduleSchema.validate(req.body, { allowUnknown: true });
  if (error) return sendError(res, 400, error.details[0].message);

  const updated = await prisma.module.update({
    where: { id },
    data: {
      ...value,
      updatedBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 200, true, 'Module updated', updated);
};

export const deleteModule = async (req: Request, res: Response) => {
  const { id } = req.params;

  await prisma.module.update({
    where: { id },
    data: {
      deletedAt: new Date(),
      isActive: false,
      updatedBy: (req as any).user.id,
    },
  });

  return sendResponse(res, 200, true, 'Module deleted successfully');
};
