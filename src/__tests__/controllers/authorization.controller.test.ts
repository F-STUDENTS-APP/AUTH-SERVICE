import { authorizeSession } from '../../controllers/authorization.controller';
import { mockRequest, mockResponse, mockPrismaClient, resetAllMocks } from '../utils/test-helpers';
import { generateAccessToken } from '../../services/token.service';

jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

jest.mock('../../services/token.service');

describe('Authorization Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('authorizeSession', () => {
    it('should authorize session and return permissions', async () => {
      req.user = {
        id: 'user-123',
        username: 'testuser',
        roles: ['ADMIN'],
      };

      const mockModuleAccess = [
        {
          module: { code: 'USERS', name: 'Users' },
          canView: true,
          canCreate: true,
          canUpdate: true,
          canDelete: true,
          canViewAll: true,
          canDownload: false,
          canApprove: false,
        },
        {
          module: { code: 'REPORTS', name: 'Reports' },
          canView: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          canViewAll: false,
          canDownload: true,
          canApprove: false,
        },
      ];

      mockPrismaClient.moduleAccess.findMany.mockResolvedValue(mockModuleAccess);
      (generateAccessToken as jest.Mock).mockReturnValue('authorized-token');

      await authorizeSession(req, res);

      expect(mockPrismaClient.moduleAccess.findMany).toHaveBeenCalled();
      expect(generateAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ isAuthorized: true })
      );
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          data: expect.objectContaining({
            accessToken: 'authorized-token',
            permissions: expect.any(Object),
          }),
        })
      );
    });

    it('should return 401 if user is not authenticated', async () => {
      req.user = null;

      await authorizeSession(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: 'Unauthorized',
        })
      );
    });

    it('should aggregate permissions from multiple roles', async () => {
      req.user = {
        id: 'user-123',
        username: 'testuser',
        roles: ['ADMIN', 'USER'],
      };

      const mockModuleAccess = [
        {
          module: { code: 'USERS', name: 'Users' },
          canView: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          canViewAll: false,
          canDownload: false,
          canApprove: false,
        },
        {
          module: { code: 'USERS', name: 'Users' },
          canView: true,
          canCreate: true,
          canUpdate: true,
          canDelete: true,
          canViewAll: true,
          canDownload: false,
          canApprove: true,
        },
      ];

      mockPrismaClient.moduleAccess.findMany.mockResolvedValue(mockModuleAccess);
      (generateAccessToken as jest.Mock).mockReturnValue('token');

      await authorizeSession(req, res);

      const call = (res.json as jest.Mock).mock.calls[0][0];
      expect(call.data.permissions.USERS.canCreate).toBe(true);
      expect(call.data.permissions.USERS.canApprove).toBe(true);
    });
  });
});
