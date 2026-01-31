import { getRoles, createRole, updateRole, deleteRole } from '../../controllers/role.controller';
import {
  mockRequest,
  mockResponse,
  mockPrismaClient,
  mockRole,
  resetAllMocks,
} from '../utils/test-helpers';

// Mock dependencies
jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

describe('Role Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('getRoles', () => {
    it('should return paginated list of roles', async () => {
      const mockRoles = [mockRole, { ...mockRole, id: 'role-2', code: 'USER' }];

      req.headers = {
        'x-paging-offset': '0',
        'x-paging-limit': '25',
      };

      mockPrismaClient.role.findMany.mockResolvedValue(mockRoles);
      mockPrismaClient.role.count.mockResolvedValue(2);

      await getRoles(req, res);

      expect(mockPrismaClient.role.findMany).toHaveBeenCalled();
      expect(mockPrismaClient.role.count).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          data: expect.objectContaining({
            items: mockRoles,
            pagination: expect.any(Object),
          }),
        })
      );
    });

    it('should filter roles by search term', async () => {
      req.headers = {
        'x-paging-offset': '0',
        'x-paging-limit': '25',
        'x-paging-search': 'admin',
      };

      mockPrismaClient.role.findMany.mockResolvedValue([mockRole]);
      mockPrismaClient.role.count.mockResolvedValue(1);

      await getRoles(req, res);

      expect(mockPrismaClient.role.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            OR: expect.any(Array),
          }),
        })
      );
    });
  });

  describe('createRole', () => {
    it('should create new role successfully', async () => {
      const newRoleData = {
        code: 'TEACHER',
        name: 'Teacher',
        description: 'Teacher role',
        isActive: true,
      };

      req.body = newRoleData;
      req.user = { id: 'admin-id' };

      mockPrismaClient.role.findUnique.mockResolvedValue(null);
      mockPrismaClient.role.create.mockResolvedValue({ id: 'new-role', ...newRoleData });

      await createRole(req, res);

      expect(mockPrismaClient.role.findUnique).toHaveBeenCalledWith({
        where: { code: 'TEACHER' },
      });
      expect(mockPrismaClient.role.create).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
    });

    it('should return 400 if role code already exists', async () => {
      req.body = { code: 'ADMIN', name: 'Admin' };

      mockPrismaClient.role.findUnique.mockResolvedValue(mockRole);

      await createRole(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: 'Role code already exists',
        })
      );
    });

    it('should return 400 on validation error', async () => {
      req.body = { code: '', name: '' }; // Invalid data

      await createRole(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });
  });

  describe('updateRole', () => {
    it('should update role successfully', async () => {
      const updateData = { name: 'Updated Admin' };

      req.params = { id: 'role-123' };
      req.body = updateData;
      req.user = { id: 'admin-id' };

      mockPrismaClient.role.findUnique.mockResolvedValue({ ...mockRole, isSystem: false });
      mockPrismaClient.role.update.mockResolvedValue({ ...mockRole, ...updateData });

      await updateRole(req, res);

      expect(mockPrismaClient.role.update).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 404 if role not found', async () => {
      req.params = { id: 'non-existent' };
      req.body = { name: 'Test' };

      mockPrismaClient.role.findUnique.mockResolvedValue(null);

      await updateRole(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
    });

    it('should return 403 if trying to update system role', async () => {
      req.params = { id: 'role-123' };
      req.body = { name: 'Test' };

      mockPrismaClient.role.findUnique.mockResolvedValue({ ...mockRole, isSystem: true });

      await updateRole(req, res);

      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('deleteRole', () => {
    it('should soft delete role successfully', async () => {
      req.params = { id: 'role-123' };
      req.user = { id: 'admin-id' };

      mockPrismaClient.role.findUnique.mockResolvedValue({ ...mockRole, isSystem: false });
      mockPrismaClient.role.update.mockResolvedValue({ ...mockRole, deletedAt: new Date() });

      await deleteRole(req, res);

      expect(mockPrismaClient.role.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            deletedAt: expect.any(Date),
            isActive: false,
          }),
        })
      );
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 404 if role not found', async () => {
      req.params = { id: 'non-existent' };

      mockPrismaClient.role.findUnique.mockResolvedValue(null);

      await deleteRole(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
    });

    it('should return 403 if trying to delete system role', async () => {
      req.params = { id: 'role-123' };

      mockPrismaClient.role.findUnique.mockResolvedValue({ ...mockRole, isSystem: true });

      await deleteRole(req, res);

      expect(res.status).toHaveBeenCalledWith(403);
    });
  });
});
