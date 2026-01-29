import swaggerJsdoc from 'swagger-jsdoc';

// Dynamically determine server URLs based on environment
const getServers = () => {
  const servers = [];

  // Production server (Vercel)
  if (process.env.VERCEL_URL) {
    servers.push({
      url: `https://${process.env.VERCEL_URL}/api/v1`,
      description: 'Production server (Vercel)',
    });
  }

  // Custom production URL
  if (process.env.PRODUCTION_URL) {
    servers.push({
      url: `${process.env.PRODUCTION_URL}/api/v1`,
      description: 'Production server',
    });
  }

  // Local development
  servers.push({
    url: `http://localhost:${process.env.PORT || 3001}/api/v1`,
    description: 'Development server',
  });

  return servers;
};

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Auth Service API',
      version: '1.0.0',
      description: 'Authentication and Authorization Service API Documentation',
    },
    servers: getServers(),
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        Error: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'error' },
            message: { type: 'string', example: 'Internal Server Error' },
          },
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [
    './src/routes/*.ts', // Development (TypeScript)
    './dist/routes/*.js', // Production (Compiled JavaScript)
  ],
};

const swaggerSpec = swaggerJsdoc(options);

export default swaggerSpec;
