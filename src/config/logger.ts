import winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Detect if running in Vercel serverless environment
const isVercel = process.env.VERCEL === '1' || process.env.VERCEL_ENV !== undefined;

// Create transports array - always include console
const transports: winston.transport[] = [
  new winston.transports.Console({
    format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
  }),
];

// Only add file transport in non-serverless environments
// Vercel has a read-only filesystem, so file logging will fail
if (!isVercel) {
  transports.push(
    new winston.transports.DailyRotateFile({
      filename: path.join(process.env.LOG_FILE_PATH || './logs', 'auth-service-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
    })
  );
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports,
});

export default logger;
