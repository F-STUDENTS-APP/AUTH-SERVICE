import bcrypt from 'bcryptjs';

export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

export const validatePasswordStrength = (password: string): boolean => {
  const minLength = parseInt(process.env.PASSWORD_MIN_LENGTH || '8');
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[@$!%*?&]/.test(password);

  if (password.length < minLength) return false;
  if (process.env.PASSWORD_REQUIRE_UPPERCASE === 'true' && !hasUpperCase) return false;
  if (process.env.PASSWORD_REQUIRE_LOWERCASE === 'true' && !hasLowerCase) return false;
  if (process.env.PASSWORD_REQUIRE_NUMBER === 'true' && !hasNumber) return false;
  if (process.env.PASSWORD_REQUIRE_SPECIAL === 'true' && !hasSpecial) return false;

  return true;
};
