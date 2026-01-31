import { Request, Response } from 'express';

/**
 * Mock Express Request object
 */
export const mockRequest = (data: Partial<Request> = {}): Partial<Request> => {
  return {
    body: {},
    params: {},
    query: {},
    headers: {},
    ip: '127.0.0.1',
    ...data,
  };
};

/**
 * Mock Express Response object
 */
export const mockResponse = (): Partial<Response> => {
  const res: Partial<Response> = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
  };
  return res;
};

/**
 * Mock Prisma Client
 */
export const mockPrismaClient: Record<string, any> = {
  user: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  role: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    count: jest.fn(),
  },
  module: {
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  refreshToken: {
    findUnique: jest.fn(),
    create: jest.fn(),
    updateMany: jest.fn(),
    deleteMany: jest.fn(),
  },
  loginHistory: {
    create: jest.fn(),
  },
  passwordResetToken: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  passwordHistory: {
    create: jest.fn(),
  },
  moduleAccess: {
    findMany: jest.fn(),
  },
  $transaction: jest.fn((callback: (client: any) => Promise<any>) => callback(mockPrismaClient)),
};

/**
 * Generate mock JWT token
 */
export const generateMockToken = (_payload: unknown = { userId: '123' }): string => {
  return 'mock.jwt.token';
};

/**
 * Mock user data for testing
 */
export const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  username: 'testuser',
  password: '$2a$10$hashedpassword', // Hashed password
  fullName: 'Test User',
  isActive: true,
  isVerified: true,
  failedLoginAttempts: 0,
  lockedUntil: null,
  lastLoginAt: new Date(),
  createdAt: new Date(),
  updatedAt: new Date(),
};

/**
 * Mock role data
 */
export const mockRole = {
  id: 'role-123',
  code: 'ADMIN',
  name: 'Administrator',
  description: 'System Administrator',
  isActive: true,
  canRequestAccess: false,
  createdAt: new Date(),
  updatedAt: new Date(),
};

/**
 * Reset all mocks
 */
export const resetAllMocks = () => {
  Object.values(mockPrismaClient).forEach((model: any) => {
    if (typeof model === 'object') {
      Object.values(model).forEach((method: unknown) => {
        if (typeof method === 'object' && method !== null && 'mockReset' in (method as any)) {
          (method as { mockReset: () => void }).mockReset();
        }
      });
    }
  });
};
