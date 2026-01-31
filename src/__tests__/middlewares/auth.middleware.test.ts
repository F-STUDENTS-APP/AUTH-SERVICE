import { authenticate, authorize } from '../../middlewares/auth.middleware';
import { verifyAccessToken } from '../../services/token.service';
import {
  mockRequest,
  mockResponse,
  mockPrismaClient,
  resetAllMocks,
  mockUser,
} from '../utils/test-helpers';

jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

jest.mock('../../services/token.service');

describe('Auth Middleware', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;
  let next: jest.Mock;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    next = jest.fn();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('authenticate', () => {
    it('should authenticate valid token and set user', async () => {
      req.headers = {
        authorization: 'Bearer valid-token',
      };
      req.path = '/some-path';
      req.method = 'GET';

      const decodedToken = {
        id: 'user-123',
        username: 'testuser',
        roles: ['USER'],
        isAuthorized: true,
      };

      const userWithRoles = {
        ...mockUser,
        userRoles: [{ role: { code: 'USER', name: 'User' } }],
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(decodedToken);
      mockPrismaClient.user.findUnique.mockResolvedValue(userWithRoles);

      await authenticate(req, res, next);

      expect(verifyAccessToken).toHaveBeenCalledWith('valid-token');
      expect(mockPrismaClient.user.findUnique).toHaveBeenCalled();
      expect(req.user).toBeDefined();
      expect(req.user.id).toBe('user-123');
      expect(next).toHaveBeenCalled();
    });

    it('should return 401 if no authorization header', async () => {
      req.headers = {};

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Unauthorized: No token provided',
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is invalid', async () => {
      req.headers = {
        authorization: 'Bearer invalid-token',
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(null);

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if token is not authorized', async () => {
      req.headers = {
        authorization: 'Bearer unauth-token',
      };
      req.path = '/some-path';
      req.method = 'POST';

      const decodedToken = {
        id: 'user-123',
        isAuthorized: false,
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(decodedToken);

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('should allow unauthorized token for /authorize endpoint', async () => {
      req.headers = {
        authorization: 'Bearer token',
      };
      req.path = '/auth/authorize';
      req.method = 'GET';

      const decodedToken = {
        id: 'user-123',
        username: 'testuser',
        roles: ['USER'],
        isAuthorized: false,
      };

      const userWithRoles = {
        ...mockUser,
        userRoles: [{ role: { code: 'USER' } }],
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(decodedToken);
      mockPrismaClient.user.findUnique.mockResolvedValue(userWithRoles);

      await authenticate(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should return 401 if user is inactive', async () => {
      req.headers = {
        authorization: 'Bearer valid-token',
      };

      const decodedToken = {
        id: 'user-123',
        isAuthorized: true,
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(decodedToken);
      mockPrismaClient.user.findUnique.mockResolvedValue({
        ...mockUser,
        isActive: false,
      });

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if user not found', async () => {
      req.headers = {
        authorization: 'Bearer valid-token',
      };

      const decodedToken = {
        id: 'user-123',
        isAuthorized: true,
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(decodedToken);
      mockPrismaClient.user.findUnique.mockResolvedValue(null);

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe('authorize', () => {
    it('should allow access if user has required role', () => {
      req.user = {
        id: 'user-123',
        roles: ['ADMIN', 'USER'],
      };

      const middleware = authorize(['ADMIN']);
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should allow SUPERADMIN to access any resource', () => {
      req.user = {
        id: 'user-123',
        roles: ['SUPERADMIN'],
      };

      const middleware = authorize(['CUSTOM_ROLE']);
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should return 403 if user does not have required role', () => {
      req.user = {
        id: 'user-123',
        roles: ['USER'],
      };

      const middleware = authorize(['ADMIN']);
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if user is not authenticated', () => {
      req.user = null;

      const middleware = authorize(['ADMIN']);
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });
  });
});
