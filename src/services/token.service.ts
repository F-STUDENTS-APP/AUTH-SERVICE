import jwt from 'jsonwebtoken';

export interface TokenPayload {
  id: string;
  username: string;
  roles: string[];
  isAuthorized: boolean;
  sid?: string;
  iat?: number;
  exp?: number;
}

export const ACCESS_TOKEN_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
export const REFRESH_TOKEN_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';

export const generateAccessToken = (payload: Partial<TokenPayload>) => {
  const finalPayload = {
    ...payload,
    isAuthorized: payload.isAuthorized ?? false,
  };
  return jwt.sign(finalPayload, process.env.JWT_SECRET as string, {
    expiresIn: ACCESS_TOKEN_EXPIRY as any,
  });
};

export const generateRefreshToken = (payload: Partial<TokenPayload>) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET as string, {
    expiresIn: REFRESH_TOKEN_EXPIRY as any,
  });
};

export const verifyAccessToken = (token: string): TokenPayload | null => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET!) as TokenPayload;
  } catch (error) {
    return null;
  }
};

export const verifyRefreshToken = (token: string): TokenPayload | null => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as TokenPayload;
  } catch (error) {
    return null;
  }
};
