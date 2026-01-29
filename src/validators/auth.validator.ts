import Joi from 'joi';

export const loginSchema = Joi.object({
  username: Joi.string().min(3).max(50).required(),
  password: Joi.string().required(),
  appCode: Joi.string().optional(),
  rememberMe: Joi.boolean().optional(),
});

export interface LoginDto {
  username: string;
  password: string;
  appCode?: string;
  rememberMe?: boolean;
}

export const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain uppercase, lowercase, number, and special character',
    }),
  name: Joi.string().min(3).max(100).required(),
});

export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required(),
  confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required(),
});

export const roleSchema = Joi.object({
  code: Joi.string().uppercase().min(2).max(50).required(),
  name: Joi.string().min(3).max(100).required(),
  description: Joi.string().max(500).optional(),
  level: Joi.number().integer().min(0).max(100).default(0),
  isActive: Joi.boolean().default(true),
});

export const moduleSchema = Joi.object({
  code: Joi.string().uppercase().min(2).max(50).required(),
  name: Joi.string().min(3).max(100).required(),
  description: Joi.string().max(500).optional(),
  icon: Joi.string().max(50).optional(),
  path: Joi.string().max(200).optional(),
  parentId: Joi.string().uuid().optional().allow(null),
  order: Joi.number().integer().min(0).default(0),
  isActive: Joi.boolean().default(true),
  isVisible: Joi.boolean().default(true),
});

export const moduleAccessSchema = Joi.object({
  roleId: Joi.string().uuid().required(),
  moduleId: Joi.string().uuid().required(),
  canView: Joi.boolean().default(false),
  canCreate: Joi.boolean().default(false),
  canUpdate: Joi.boolean().default(false),
  canDelete: Joi.boolean().default(false),
  canViewAll: Joi.boolean().default(false),
  canDownload: Joi.boolean().default(false),
  canApprove: Joi.boolean().default(false),
});
