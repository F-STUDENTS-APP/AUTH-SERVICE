import request from 'supertest';
import app from '../app';
import prisma from '../config/prisma';

describe('Auth Flow', () => {
  // Clear data after tests if needed, but usually we use a separate test DB

  it('should fail login with invalid credentials', async () => {
    const res = await request(app).post('/api/v1/auth/login').send({
      username: 'nonexistentuser',
      password: 'wrongpassword',
    });

    expect(res.statusCode).toEqual(401);
    expect(res.body.success).toBe(false);
  });

  it('should fail to access protected routes without token', async () => {
    const res = await request(app).get('/api/v1/modules');
    expect(res.statusCode).toEqual(401);
  });

  it('should fail to access internal route without key', async () => {
    const res = await request(app).get('/api/v1/auth/internal/user/some-id');
    expect(res.statusCode).toEqual(401);
  });
});
