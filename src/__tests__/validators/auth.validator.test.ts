import { loginSchema } from '../../validators/auth.validator';

describe('Auth Validators', () => {
  describe('loginSchema', () => {
    it('should validate correct login data', () => {
      const validData = {
        username: 'testuser',
        password: 'Password123!',
      };

      const result = validateLogin(validData);
      expect(result.error).toBeUndefined();
      expect(result.value).toEqual(validData);
    });

    it('should reject empty username', () => {
      const invalidData = {
        username: '',
        password: 'Password123!',
      };

      const result = validateLogin(invalidData);
      expect(result.error).toBeDefined();
    });

    it('should reject empty password', () => {
      const invalidData = {
        username: 'testuser',
        password: '',
      };

      const result = validateLogin(invalidData);
      expect(result.error).toBeDefined();
    });

    it('should reject if username is missing', () => {
      const invalidData = {
        password: 'Password123!',
      } as unknown;

      const result = validateLogin(invalidData);
      expect(result.error).toBeDefined();
    });

    it('should reject if password is missing', () => {
      const invalidData = {
        username: 'testuser',
      } as unknown;

      const result = validateLogin(invalidData);
      expect(result.error).toBeDefined();
    });
  });
});

// Helper function since validators may export schema directly
function validateLogin(data: unknown) {
  return loginSchema.validate(data);
}
