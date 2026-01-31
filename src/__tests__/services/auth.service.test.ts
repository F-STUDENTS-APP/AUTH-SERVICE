import { authService } from '../../services/auth.service';
import { mockPrismaClient, mockUser, resetAllMocks } from '../utils/test-helpers';
import { comparePassword } from '../../services/password.service';
import { generateAccessToken, generateRefreshToken } from '../../services/token.service';

// Mock dependencies
jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

jest.mock('../../services/password.service');
jest.mock('../../services/token.service');

describe('AuthService', () => {
  beforeEach(() => {
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('login', () => {
    const loginData = { username: 'testuser', password: 'Password123!' };
    const ipAddress = '127.0.0.1';
    const userAgent = 'Jest Test';

    it('should successfully login user with valid credentials', async () => {
      const mockUserWithRoles = {
        ...mockUser,
        userRoles: [{ role: { code: 'ADMIN', name: 'Administrator', id: 'role-1' } }],
      };

      mockPrismaClient.user.findFirst.mockResolvedValue(mockUserWithRoles);
      (comparePassword as jest.Mock).mockResolvedValue(true);
      (generateAccessToken as jest.Mock).mockReturnValue('access-token');
      (generateRefreshToken as jest.Mock).mockReturnValue('refresh-token');

      mockPrismaClient.$transaction.mockImplementation(
        async (callback: (client: any) => Promise<any>) => {
          mockPrismaClient.user.update.mockResolvedValue(mockUserWithRoles);
          mockPrismaClient.refreshToken.create.mockResolvedValue({});
          mockPrismaClient.loginHistory.create.mockResolvedValue({});
          return callback(mockPrismaClient);
        }
      );

      const result = await authService.login(loginData, ipAddress, userAgent);

      expect(mockPrismaClient.user.findFirst).toHaveBeenCalled();
      expect(comparePassword).toHaveBeenCalledWith('Password123!', mockUser.password);
      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('tokens');
      expect(result.tokens).toHaveProperty('accessToken', 'access-token');
      expect(result.tokens).toHaveProperty('refreshToken', 'refresh-token');
    });

    it('should throw error if user not found', async () => {
      mockPrismaClient.user.findFirst.mockResolvedValue(null);

      await expect(authService.login(loginData, ipAddress, userAgent)).rejects.toEqual({
        status: 401,
        message: 'Invalid credentials',
      });
    });

    it('should throw error if account is inactive', async () => {
      mockPrismaClient.user.findFirst.mockResolvedValue({
        ...mockUser,
        isActive: false,
      });

      await expect(authService.login(loginData, ipAddress, userAgent)).rejects.toEqual({
        status: 401,
        message: 'Account is inactive',
      });
    });

    it('should throw error if account is locked', async () => {
      const lockedUntil = new Date(Date.now() + 60000); // 1 minute from now
      mockPrismaClient.user.findFirst.mockResolvedValue({
        ...mockUser,
        lockedUntil,
      });

      await expect(authService.login(loginData, ipAddress, userAgent)).rejects.toMatchObject({
        status: 423,
      });
    });

    it('should throw error if password is invalid', async () => {
      mockPrismaClient.user.findFirst.mockResolvedValue(mockUser);
      (comparePassword as jest.Mock).mockResolvedValue(false);

      mockPrismaClient.$transaction.mockImplementation(async (operations: Promise<unknown>[]) => {
        return Promise.all(operations);
      });

      await expect(authService.login(loginData, ipAddress, userAgent)).rejects.toEqual({
        status: 401,
        message: 'Invalid credentials',
      });
    });
  });

  describe('refreshAuth', () => {
    it('should return new access token with valid refresh token', async () => {
      const refreshToken = 'valid-refresh-token';
      const mockStoredToken = {
        token: refreshToken,
        isRevoked: false,
        expiresAt: new Date(Date.now() + 86400000), // 1 day from now
        user: {
          ...mockUser,
          userRoles: [{ role: { code: 'USER', name: 'User' } }],
        },
      };

      mockPrismaClient.refreshToken.findUnique.mockResolvedValue(mockStoredToken);
      (generateAccessToken as jest.Mock).mockReturnValue('new-access-token');

      const result = await authService.refreshAuth(refreshToken);

      expect(mockPrismaClient.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { token: refreshToken },
        include: expect.any(Object),
      });
      expect(result).toHaveProperty('accessToken', 'new-access-token');
    });

    it('should throw error if token is missing', async () => {
      await expect(authService.refreshAuth('')).rejects.toEqual({
        status: 400,
        message: 'Refresh token is required',
      });
    });

    it('should throw error if token is revoked', async () => {
      const refreshToken = 'revoked-token';
      mockPrismaClient.refreshToken.findUnique.mockResolvedValue({
        token: refreshToken,
        isRevoked: true,
        expiresAt: new Date(Date.now() + 86400000),
      });

      await expect(authService.refreshAuth(refreshToken)).rejects.toEqual({
        status: 401,
        message: 'Invalid or expired refresh token',
      });
    });

    it('should throw error if token is expired', async () => {
      const refreshToken = 'expired-token';
      mockPrismaClient.refreshToken.findUnique.mockResolvedValue({
        token: refreshToken,
        isRevoked: false,
        expiresAt: new Date(Date.now() - 86400000), // 1 day ago
      });

      await expect(authService.refreshAuth(refreshToken)).rejects.toEqual({
        status: 401,
        message: 'Invalid or expired refresh token',
      });
    });
  });

  describe('logout', () => {
    it('should revoke refresh token on logout', async () => {
      const refreshToken = 'valid-token';
      mockPrismaClient.refreshToken.updateMany.mockResolvedValue({ count: 1 });

      await authService.logout(refreshToken);

      expect(mockPrismaClient.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { token: refreshToken },
        data: {
          isRevoked: true,
          revokedAt: expect.any(Date),
        },
      });
    });

    it('should not error if token is empty', async () => {
      await expect(authService.logout('')).resolves.toBeUndefined();
      expect(mockPrismaClient.refreshToken.updateMany).not.toHaveBeenCalled();
    });
  });
});
