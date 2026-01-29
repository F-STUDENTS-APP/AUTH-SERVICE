import dotenv from 'dotenv';

dotenv.config();

export const AUTH_CONFIG = {
  ACCESS_TOKEN_EXPIRY: process.env.JWT_ACCESS_EXPIRATION || '15m',
  ACCESS_TOKEN_EXPIRY_SECONDS: 900, // 15 minutes in seconds for frontend
  REFRESH_TOKEN_EXPIRY_DAYS: parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '7'),
  MAX_LOGIN_ATTEMPTS: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
  ACCOUNT_LOCKOUT_DURATION_MINS: parseInt(process.env.ACCOUNT_LOCKOUT_DURATION || '30'),
};
