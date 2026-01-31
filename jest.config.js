module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    roots: ['<rootDir>/src'],
    testMatch: ['**/__tests__/**/*.test.ts'],
    moduleNameMapper: {
        '^@common/(.*)$': '<rootDir>/../common/$1',
        '^@/(.*)$': '<rootDir>/src/$1'
    },
    collectCoverageFrom: [
        'src/**/*.ts',
        '!src/**/*.d.ts',
        '!src/index.ts',
        '!src/__tests__/**'
    ],
    coverageThreshold: {
        global: {
            branches: 95,
            functions: 95,
            lines: 95,
            statements: 95
        }
    },
    setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
    verbose: true
};
