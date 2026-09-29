module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/jest.setup.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        diagnostics: false,
      },
    ],
    '^.+\\.m?js$': [
      'babel-jest',
      {
        presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
      },
    ],
  },
  // Jest 30 ships nested ESM-only packages (ansi-styles v6, chalk v5, etc.)
  // that must be transformed by ts-jest/babel rather than executed as-is.
  testMatch: ['<rootDir>/src/**/*.spec.ts', '<rootDir>/test/**/*.spec.ts'],
  transformIgnorePatterns: [
    '/node_modules/(?!(ansi-styles|sanitize-html|htmlparser2|domhandler|domutils|dom-serializer|domelementtype|entities)/)',
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/xconfess-backend/',
    '<rootDir>/e2e/',
  ],
  watchPathIgnorePatterns: ['<rootDir>/xconfess-backend/'],
  modulePathIgnorePatterns: ['<rootDir>/xconfess-backend/'],
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    '^@nestjs/bull$': '@nestjs/bullmq',
    '^bull$': 'bullmq',
    '^bcrypt$': 'bcryptjs',
    '^@faker-js/faker$': '<rootDir>/test/utils/faker-stub.ts',
    '^@faker-js/faker/\\.$': '<rootDir>/test/utils/faker-stub.ts',
    // ansi-styles v6+ is ESM-only; Jest (CJS) cannot parse `export`.
    // Point to a CJS shim that provides the minimal surface packages need.
    '^ansi-styles$': '<rootDir>/test/utils/ansi-styles-shim.js',
  },
  // Some specs intentionally exercise queues, sockets, and failed transports.
  // Disable Jest's one-second open-handle warning while the suite tears down.
  openHandlesTimeout: 0,

  // ---------------------------------------------------------------------------
  // Coverage collection
  // ---------------------------------------------------------------------------
  // Run with --coverage to enforce thresholds. CI uses:
  //   npx jest --coverage --coverageReporters=text-summary
  // To generate a full HTML report locally:
  //   npx jest --coverage --coverageReporters=html
  collectCoverageFrom: [
    'src/**/*.ts',
    // Intentionally test-light directories — DTOs, type definitions, and
    // migrations contain almost no logic worth unit-testing.
    '!src/**/*.dto.ts',
    '!src/**/*.entity.ts',
    '!src/**/*.module.ts',
    '!src/**/index.ts',
    '!src/migrations/**',
    '!src/main.ts',
    '!src/**/*.d.ts',
    '!src/types/**',
  ],
  coverageDirectory: 'coverage',

  // ---------------------------------------------------------------------------
  // Risk-domain coverage thresholds
  //
  // Why per-domain instead of a single global threshold?
  //
  // Aggregate coverage numbers mask gaps in the highest-risk code paths. A
  // 60% global figure looks acceptable even when auth or encryption is at 0%.
  // By enforcing per-path thresholds we make coverage drops domain-specific
  // and actionable: the CI failure tells you *which* domain regressed, not
  // just that overall coverage fell.
  //
  // Threshold values are set relative to the existing test suite. Domains
  // with rich existing specs get higher floors; domains where integration
  // tests cover the gap are set conservatively. Adjust thresholds upward as
  // test depth improves — never downward without a documented reason in the PR.
  //
  // Domain definitions:
  //   auth         — JWT, guards, session, password-reset, step-up auth
  //   encryption   — envelope encryption, confession encryption, key rotation
  //   moderation   — state machine, webhook idempotency, AI moderation
  //   stellar      — contract invocation, event parsing, reconciliation
  //   tipping      — tip verification, idempotency, chain reconciliation
  //   migration    — migration verification service
  //   admin        — admin guard, admin service, RBAC
  // ---------------------------------------------------------------------------
  coverageThreshold: {
    // Global floor — prevents overall coverage collapse while domains are
    // independently enforced below.
    global: {
      lines: 50,
      functions: 45,
      branches: 40,
      statements: 50,
    },

    // --- AUTH (high risk: session integrity, credential handling) ---
    './src/auth/': {
      lines: 70,
      functions: 65,
      branches: 55,
      statements: 70,
    },

    // --- ENCRYPTION (high risk: data confidentiality at rest) ---
    './src/encryption/': {
      lines: 70,
      functions: 65,
      branches: 55,
      statements: 70,
    },

    // --- MODERATION (medium-high risk: content policy enforcement) ---
    './src/moderation/': {
      lines: 65,
      functions: 60,
      branches: 50,
      statements: 65,
    },

    // --- STELLAR / PAYMENTS (high risk: on-chain value transfer) ---
    './src/stellar/': {
      lines: 60,
      functions: 55,
      branches: 45,
      statements: 60,
    },

    // --- TIPPING (high risk: financial operations, idempotency) ---
    './src/tipping/': {
      lines: 60,
      functions: 55,
      branches: 45,
      statements: 60,
    },

    // --- ADMIN (medium-high risk: privilege escalation surface) ---
    './src/admin/': {
      lines: 60,
      functions: 55,
      branches: 45,
      statements: 60,
    },

    // --- DATABASE / MIGRATIONS (medium risk: schema integrity) ---
    './src/database/': {
      lines: 55,
      functions: 50,
      branches: 40,
      statements: 55,
    },

    // --- AUTHORIZATION MATRIX (high risk: cross-tenant privilege escalation) ---
    './src/authz/': {
      lines: 70,
      functions: 65,
      branches: 55,
      statements: 70,
    },
  },
};
