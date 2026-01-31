import { getUserForInternal } from '../../controllers/internal.controller';
import { mockRequest, mockResponse, mockPrismaClient, resetAllMocks } from '../utils/test-helpers';

jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

describe('Internal Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('getUserForInternal', () => {
    it('should return user data for internal service call', async () => {
      req.params = { id: 'user-123' };

      const userData = {
        id: 'user-123',
        username: 'testuser',
        name: 'Test User',
        email: 'test@example.com',
        isActive: true,
      };

      mockPrismaClient.user.findUnique.mockResolvedValue(userData);

      await getUserForInternal(req, res);

      expect(mockPrismaClient.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        select: expect.any(Object),
      });
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          data: userData,
        })
      );
    });

    it('should return 404 if user not found', async () => {
      req.params = { id: 'non-existent' };

      mockPrismaClient.user.findUnique.mockResolvedValue(null);

      await getUserForInternal(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          message: 'User not found',
        })
      );
    });
  });
});
