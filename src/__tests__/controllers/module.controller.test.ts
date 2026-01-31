import { getModules, createModule, updateModule } from '../../controllers/module.controller';
import { mockRequest, mockResponse, mockPrismaClient, resetAllMocks } from '../utils/test-helpers';

jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

describe('Module Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('getModules', () => {
    it('should return list of modules', async () => {
      const mockModules = [
        { id: 'mod-1', name: 'Users', code: 'USERS', path: '/users' },
        { id: 'mod-2', name: 'Reports', code: 'REPORTS', path: '/reports' },
      ];

      mockPrismaClient.module.findMany.mockResolvedValue(mockModules);

      await getModules(req, res);

      expect(mockPrismaClient.module.findMany).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          data: mockModules,
        })
      );
    });
  });

  describe('createModule', () => {
    it('should create new module successfully', async () => {
      const newModuleData = {
        code: 'NEW_MODULE',
        name: 'New Module',
        description: 'Test module',
        path: '/new',
        icon: 'icon-test',
      };

      req.body = newModuleData;
      req.user = { id: 'admin-id' };

      mockPrismaClient.module.create.mockResolvedValue({ id: 'mod-new', ...newModuleData });

      await createModule(req, res);

      expect(mockPrismaClient.module.create).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
    });

    it('should return 400 on validation error', async () => {
      req.body = { code: '', name: '' }; // Invalid

      await createModule(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });
  });

  describe('updateModule', () => {
    it('should update module successfully', async () => {
      const updateData = { name: 'Updated Module' };

      req.params = { id: 'mod-123' };
      req.body = updateData;
      req.user = { id: 'admin-id' };

      const existingModule = { id: 'mod-123', code: 'TEST', name: 'Test' };
      mockPrismaClient.module.findUnique.mockResolvedValue(existingModule);
      mockPrismaClient.module.update.mockResolvedValue({ ...existingModule, ...updateData });

      await updateModule(req, res);

      expect(mockPrismaClient.module.update).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 404 if module not found', async () => {
      req.params = { id: 'non-existent' };
      req.body = { name: 'Test' };

      mockPrismaClient.module.findUnique.mockResolvedValue(null);

      await updateModule(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
    });
  });
});
