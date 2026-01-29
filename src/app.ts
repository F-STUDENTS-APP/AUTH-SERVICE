import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import 'express-async-errors';
import dotenv from 'dotenv';
import logger from './config/logger';
import { sendError } from './utils/response';
import swaggerUi from 'swagger-ui-express';
import swaggerSpec from './config/swagger';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
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

app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'OK', service: 'auth-service' });
});

// Root redirect to API docs
app.get('/', (req: Request, res: Response) => {
  res.redirect('/api-docs');
});

// Swagger Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error(err.stack);
  const status = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  sendError(res, status, message);
});

// Only start the server if not in test or serverless environment
// Vercel will use the exported app directly
const isVercel = process.env.VERCEL === '1' || process.env.VERCEL_ENV !== undefined;

if (process.env.NODE_ENV !== 'test' && !isVercel) {
  app.listen(port, () => {
    logger.info(`Auth Service listening on port ${port}`);
  });
}

export default app;
