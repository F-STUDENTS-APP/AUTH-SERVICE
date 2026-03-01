import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import 'express-async-errors';
import dotenv from 'dotenv';
import logger from './config/logger';
import swaggerUi from 'swagger-ui-express';
import swaggerSpec from './config/swagger';
import { errorHandler } from '@microservices/common/middlewares/error.handler';
import { healthCheck } from '@microservices/common/utils/health';

import rateLimit from 'express-rate-limit';
import { AUTH_CONFIG } from './config/constants';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Trust proxy if behind LB/Vercel
if (process.env.NODE_ENV === 'production' || process.env.VERCEL === '1') {
  app.set('trust proxy', 1);
}

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 mins
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
          .map((o) => o.trim())
          .filter((o) => o && o !== '*')
      : [],
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Routes
import authRoutes from './routes/auth.routes';
import roleRoutes from './routes/role.routes';
import moduleRoutes from './routes/module.routes';

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/roles', roleRoutes);
app.use('/api/v1/modules', moduleRoutes);

app.get('/health', healthCheck('auth-service'));

// Root redirect to API docs
app.get('/', (req: Request, res: Response) => {
  res.redirect('/api-docs');
});

// Swagger Documentation
const swaggerOptions = {
  customCssUrl: 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui.min.css',
  customJs: [
    'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-bundle.min.js',
    'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-standalone-preset.min.js',
  ],
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, swaggerOptions));

// Error handling
app.use(errorHandler);

// Only start the server if not in test or serverless environment
// Vercel will use the exported app directly
const isVercel = process.env.VERCEL === '1' || process.env.VERCEL_ENV !== undefined;

if (process.env.NODE_ENV !== 'test' && !isVercel) {
  app.listen(port, () => {
    logger.info(`Auth Service listening on port ${port}`);
  });
}

export default app;
