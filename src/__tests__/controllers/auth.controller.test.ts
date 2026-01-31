import { login, refreshToken, logout } from '../../controllers/auth.controller';
import { authService } from '../../services/auth.service';
import { mockRequest, mockResponse } from '../utils/test-helpers';

// Mock the auth service
jest.mock('../../services/auth.service');

describe('Auth Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    jest.clearAllMocks();
  });

  describe('login', () => {
    it('should return 200 and tokens on successful login', async () => {
      const mockLoginData = {
        username: 'testuser',
        password: 'Password123!',
      };

      const mockResult = {
        user: {
          id: 'user-123',
          email: 'test@example.com',
          username: 'testuser',
          name: 'Test User',
          roles: ['ADMIN'],
        },
        tokens: {
          accessToken: 'mock-access-token',
          refreshToken: 'mock-refresh-token',
          expiresIn: 3600,
        },
      };

      req.body = mockLoginData;
      req.ip = '127.0.0.1';
      req.headers = { 'user-agent': 'Jest Test' };

      (authService.login as jest.Mock).mockResolvedValue(mockResult);

      await login(req, res);

      expect(authService.login).toHaveBeenCalledWith(mockLoginData, '127.0.0.1', 'Jest Test');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Login successful',
        })
      );
    });

    it('should return 400 on validation error', async () => {
      req.body = {
        username: '', // Empty username
        password: '123', // Too short
      };

      await login(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
        })
      );
    });

    it('should return error on service error', async () => {
      req.body = {
        username: 'testuser',
        password: 'Password123!',
      };

      const error: Error & { status?: number } = new Error('Database connection failed');
      error.status = 500;
      (authService.login as jest.Mock).mockRejectedValue(error);

      await login(req, res);

      expect(res.status).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
        })
      );
    });

    it('should return 401 on invalid credentials', async () => {
      req.body = {
        username: 'testuser',
        password: 'WrongPassword',
      };

      const error: Error & { status?: number } = new Error('Invalid credentials');
      error.status = 401;
      (authService.login as jest.Mock).mockRejectedValue(error);

      await login(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
        })
      );
    });
  });

  describe('refreshToken', () => {
    it('should return new tokens on valid refresh token', async () => {
      const mockRefreshToken = 'valid-refresh-token';
      const mockResult = {
        accessToken: 'new-access-token',
        expiresIn: 3600,
      };

      req.headers = { 'x-refresh-token': mockRefreshToken };

      (authService.refreshAuth as jest.Mock).mockResolvedValue(mockResult);

      await refreshToken(req, res);

      expect(authService.refreshAuth).toHaveBeenCalledWith(mockRefreshToken);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Token refreshed',
        })
      );
    });

    it('should return 401 on invalid refresh token', async () => {
      req.headers = { 'x-refresh-token': 'invalid-token' };

      const error: Error & { status?: number } = new Error('Invalid refresh token');
      error.status = 401;
      (authService.refreshAuth as jest.Mock).mockRejectedValue(error);

      await refreshToken(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe('logout', () => {
    it('should return 200 on successful logout', async () => {
      req.body = { refreshToken: 'valid-refresh-token' };

      (authService.logout as jest.Mock).mockResolvedValue(undefined);

      await logout(req, res);

      expect(authService.logout).toHaveBeenCalledWith('valid-refresh-token');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Logout successful',
        })
      );
    });

    it('should handle logout errors gracefully', async () => {
      req.body = { refreshToken: 'some-token' };

      const error: Error & { status?: number } = new Error('Token not found');
      error.status = 500;
      (authService.logout as jest.Mock).mockRejectedValue(error);

      await logout(req, res);

      expect(res.status).toHaveBeenCalled();
    });
  });
});
