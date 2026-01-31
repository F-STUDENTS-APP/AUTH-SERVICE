import {
  forgotPassword,
  resetPassword,
  changePassword,
} from '../../controllers/password.controller';
import {
  mockRequest,
  mockResponse,
  mockPrismaClient,
  resetAllMocks,
  mockUser,
} from '../utils/test-helpers';
import {
  hashPassword,
  comparePassword,
  validatePasswordStrength,
} from '../../services/password.service';
import axios from 'axios';

jest.mock('../../config/prisma', () => ({
  __esModule: true,
  default: mockPrismaClient,
}));

jest.mock('../../services/password.service');
jest.mock('axios');

describe('Password Controller', () => {
  let req: Partial<Request> | any;
  let res: Partial<Response> | any;

  beforeEach(() => {
    req = mockRequest();
    res = mockResponse();
    resetAllMocks();
    jest.clearAllMocks();
  });

  describe('forgotPassword', () => {
    it('should create reset token and send email', async () => {
      req.body = { email: 'test@example.com' };

      mockPrismaClient.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaClient.passwordResetToken.create.mockResolvedValue({ token: 'reset-token' });
      (axios.post as jest.Mock).mockResolvedValue({});

      await forgotPassword(req, res);

      expect(mockPrismaClient.passwordResetToken.create).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 400 if email is missing', async () => {
      req.body = {};

      await forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Email is required' })
      );
    });

    it('should return success even if user not found (security)', async () => {
      req.body = { email: 'nonexistent@example.com' };

      mockPrismaClient.user.findUnique.mockResolvedValue(null);

      await forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(mockPrismaClient.passwordResetToken.create).not.toHaveBeenCalled();
    });

    it('should still succeed if email notification fails', async () => {
      req.body = { email: 'test@example.com' };

      mockPrismaClient.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaClient.passwordResetToken.create.mockResolvedValue({});
      (axios.post as jest.Mock).mockRejectedValue(new Error('Network error'));

      await forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
    });
  });

  describe('resetPassword', () => {
    it('should reset password with valid token', async () => {
      req.body = {
        token: 'valid-token',
        newPassword: 'NewPassword123!',
        confirmPassword: 'NewPassword123!',
      };

      const mockResetToken = {
        id: 'token-id',
        email: 'test@example.com',
        token: 'valid-token',
        isUsed: false,
        expiresAt: new Date(Date.now() + 3600000),
      };

      mockPrismaClient.passwordResetToken.findUnique.mockResolvedValue(mockResetToken);
      mockPrismaClient.user.findUnique.mockResolvedValue(mockUser);
      (validatePasswordStrength as jest.Mock).mockReturnValue(true);
      (hashPassword as jest.Mock).mockResolvedValue('hashed-password');

      mockPrismaClient.$transaction.mockImplementation(async (operations: Promise<unknown>[]) => {
        return Promise.all(operations);
      });

      await resetPassword(req, res);

      expect(mockPrismaClient.$transaction).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 400 if passwords do not match', async () => {
      req.body = {
        token: 'token',
        newPassword: 'Password123!',
        confirmPassword: 'DifferentPassword123!',
      };

      await resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Passwords do not match' })
      );
    });

    it('should return 400 if password is weak', async () => {
      req.body = {
        token: 'token',
        newPassword: 'weak',
        confirmPassword: 'weak',
      };

      (validatePasswordStrength as jest.Mock).mockReturnValue(false);

      await resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should return 400 if token is expired', async () => {
      req.body = {
        token: 'expired-token',
        newPassword: 'Password123!',
        confirmPassword: 'Password123!',
      };

      mockPrismaClient.passwordResetToken.findUnique.mockResolvedValue({
        token: 'expired-token',
        isUsed: false,
        expiresAt: new Date(Date.now() - 3600000), // Expired
      });

      (validatePasswordStrength as jest.Mock).mockReturnValue(true);

      await resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should return 400 if token is already used', async () => {
      req.body = {
        token: 'used-token',
        newPassword: 'Password123!',
        confirmPassword: 'Password123!',
      };

      mockPrismaClient.passwordResetToken.findUnique.mockResolvedValue({
        token: 'used-token',
        isUsed: true,
        expiresAt: new Date(Date.now() + 3600000),
      });

      (validatePasswordStrength as jest.Mock).mockReturnValue(true);

      await resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });
  });

  describe('changePassword', () => {
    it('should change password successfully', async () => {
      req.body = {
        currentPassword: 'OldPassword123!',
        newPassword: 'NewPassword123!',
        confirmPassword: 'NewPassword123!',
      };

      req.user = { id: 'user-123' };

      mockPrismaClient.user.findUnique.mockResolvedValue(mockUser);
      (comparePassword as jest.Mock).mockResolvedValue(true);
      (hashPassword as jest.Mock).mockResolvedValue('new-hashed-password');

      mockPrismaClient.$transaction.mockImplementation(async (operations: Promise<unknown>[]) => {
        return Promise.all(operations);
      });

      await changePassword(req, res);

      expect(mockPrismaClient.$transaction).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it('should return 401 if current password is incorrect', async () => {
      req.body = {
        currentPassword: 'WrongPassword',
        newPassword: 'NewPassword123!',
        confirmPassword: 'NewPassword123!',
      };

      req.user = { id: 'user-123' };

      mockPrismaClient.user.findUnique.mockResolvedValue(mockUser);
      (comparePassword as jest.Mock).mockResolvedValue(false);

      await changePassword(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should return 400 on validation error', async () => {
      req.body = {
        currentPassword: '',
        newPassword: '',
      };

      req.user = { id: 'user-123' };

      await changePassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
    });
  });
});
