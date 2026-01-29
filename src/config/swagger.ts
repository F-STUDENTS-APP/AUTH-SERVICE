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

// Define OpenAPI spec directly (Inline) to avoid file scanning issues in serverless
const swaggerDefinition = {
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
  paths: {
    '/auth/login': {
      post: {
        summary: 'User login',
        tags: ['Auth'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['username', 'password'],
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          '200': { description: 'Login successful' },
          '401': { description: 'Invalid credentials' },
        },
      },
    },
    '/auth/logout': {
      post: {
        summary: 'User logout',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Logout successful' },
        },
      },
    },
    '/auth/token/refresh': {
      get: {
        summary: 'Refresh access token',
        tags: ['Auth'],
        responses: {
          '200': { description: 'Token refreshed' },
          '401': { description: 'Invalid/expired refresh token' },
        },
      },
    },
    '/auth/authorize': {
      get: {
        summary: 'Get module permissions and final authorized token',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Auth success' },
          '403': { description: 'Forbidden' },
        },
      },
    },
  },
  tags: [{ name: 'Auth', description: 'Authentication management' }],
};

const options: swaggerJsdoc.Options = {
  definition: swaggerDefinition as any,
  apis: [], // Disable file scanning
};

const swaggerSpec = swaggerJsdoc(options);

export default swaggerSpec;
