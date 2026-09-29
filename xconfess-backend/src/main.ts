import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerExceptionFilter } from './common/filters/throttler-exception.filter';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { RequestIdMiddleware } from './middleware/request-id.middleware';
import { WebSocketAdapter } from './websocket/websocket.adapter';
import { AppLogger } from './logger/logger.service';
import { configureRequestBodyParsing } from './common/request-body-limits';

import {
  cookieParserMiddleware,
  csrfMiddleware,
  csrfCookieSetter,
} from './common/middleware/middleware';

/**
 * Content-Security-Policy ownership.
 *
 * The frontend proxy and the backend must agree on a single policy before
 * enforcement. This module is the backend's authoritative source of truth for
 * the CSP directives and for the report-only / enforce rollout switch.
 *
 * Rollout model:
 *   - CSP_MODE=report-only (default) -> sends Content-Security-Policy-Report-Only
 *   - CSP_MODE=enforce              -> sends Content-Security-Policy
 *   - CSP_MODE=disabled             -> no CSP header at all (kill-switch)
 *
 * Reports are collected at CSP_REPORT_URI and are sanitized by the browser
 * (see docs/security/csp-rollout.md). The backend never logs the raw
 * report body and the report endpoint is exempt from CSRF because browsers
 * send these without credentials.
 */

export type CspMode = 'report-only' | 'enforce' | 'disabled';

export interface CspPolicy {
  mode: CspMode;
  directives: Record<string, string[]>;
  reportUri?: string;
}

const DEFAULT_CSP_REPORT_URI = '/api/security/csp-report';

const DEFAULT_CSP_DIRECTIVES: Record<string, string[]> = {
  defaultSrc: ['self'],
  scriptSrc: ['self'],
  styleSrc: ['self', 'unsafe-inline'],
  imgSrc: ['self', 'data:', 'https:'],
  fontSrc: ['self', 'data:'],
  connectSrc: ['self'],
  frameSrc: ['none'],
  frameAncestors: ['none'],
  objectSrc: ['none'],
  baseUri: ['self'],
  formAction: ['self'],
  upgradeInsecureRequests: [],
};

function parseCspMode(raw: string | undefined): CspMode {
  const normalized = (raw ?? 'report-only').trim().toLowerCase();
  if (normalized === 'enforce') return 'enforce';
  if (normalized === 'disabled') return 'disabled';
  return 'report-only';
}

function parseCspDirectives(
  raw: string | undefined,
): Record<string, string[]> {
  if (!raw) return { ...DEFAULT_CSP_DIRECTIVES };
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: Record<string, string[]> = { ...DEFAULT_CSP_DIRECTIVES };
    for (const [key, value] of Object.entries(parsed)) {
      if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
        out[key] = value as string[];
      }
    }
    return out;
  } catch {
    return { ...DEFAULT_CSP_DIRECTIVES };
  }
}

export function resolveCspPolicy(configService: ConfigService): CspPolicy {
  const mode = parseCspMode(configService.get<string>('CSP_MODE'));
  const directives = parseCspDirectives(
    configService.get<string>('CSP_DIRECTIVES'),
  );
  const reportUri =
    configService.get<string>('CSP_REPORT_URI') ?? DEFAULT_CSP_REPORT_URI;
  return { mode, directives, reportUri };
}

function buildHelmetOptions(policy: CspPolicy): Parameters<typeof helmet>[0] {
  const contentSecurityPolicy =
    policy.mode === 'disabled'
      ? false
      : {
          useDefaults: false,
          directives: policy.directives,
          reportOnly: policy.mode === 'report-only',
          ...(policy.reportUri
            ? { reportUri: policy.reportUri }
            : {}),
        };

  return {
    contentSecurityPolicy,
    // helmet v7 removed the xssFilter / noSniff shorthand aliases;
    // xssProtection and noSniff are enabled by default — no need to re-declare.
    frameguard: { action: 'deny' },
  };
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: false });
  const configService = app.get(ConfigService);

  // ── 1. Request-ID must be first so all downstream code sees it ───────────────
  const requestIdMiddleware = new RequestIdMiddleware();
  app.use(requestIdMiddleware.use.bind(requestIdMiddleware));

  // Apply targeted limits before Nest validation pipes and controller code.
  configureRequestBodyParsing(app);

  app.enableShutdownHooks();

  // ── 2. Security headers — single authoritative path for all HTTP responses ──
  //    SecurityMiddleware is intentionally NOT registered as a Nest middleware
  //    because it was never wired into the middleware consumer.  Applying Helmet
  //    here in bootstrap ensures it runs on every request without exception.
  //    CSP directives and the report-only / enforce switch are owned here and
  //    are documented in docs/security/csp-rollout.md.
  const cspPolicy = resolveCspPolicy(configService);
  app.use(helmet(buildHelmetOptions(cspPolicy)));

  // ── 3. CORS — one allowed origin derived from config ───────────────────────
  //    Both HTTP and the WebSocket adapter read FRONTEND_URL so there is a
  //    single documented source of truth for allowed origins.
  const frontendUrl =
    configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';

  app.enableCors({
    origin: frontendUrl,
    credentials: true,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  });

  // ── 4. WebSocket adapter — reads the same FRONTEND_URL ──────────────────────
  app.useWebSocketAdapter(new WebSocketAdapter(app, configService));

  // ── 5. Compression ──────────────────────────────────────────────────────────
  app.use(
    compression({
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false;
        }
        return compression.filter(req, res);
      },
      threshold: 1024,
    }),
  );

  // ── 6. Cookie parser (required by csurf) ───────────────────────────────────
  app.use(cookieParserMiddleware);

  // ── 7. CSRF protection ────────────────────────────────────────────────────────────────────────
  //    Webhooks are exempt because they use HMAC signature verification instead.
  //    Public account-entry routes are exempt because the Next.js proxy calls
  //    them server-side before a browser CSRF cookie exists.
  const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
  const csrfExemptRoutes = new Set([
    'POST /api/auth/login',
    'POST /api/auth/2fa/login',
    'POST /api/auth/forgot-password',
    'POST /api/auth/reset-password',
    'POST /api/users/register',
  ]);

  app.use((req, res, next) => {
    const routeKey = `${req.method.toUpperCase()} ${req.path}`;
    if (safeMethods.has(req.method.toUpperCase())) {
      csrfCookieSetter(req as any, res as any, next);
      return;
    }
    if (
      req.path.startsWith('/api/webhooks/moderation') ||
      req.path === '/api/security/csp-report' ||
      csrfExemptRoutes.has(routeKey)
    ) {
      return next();
    }
    csrfMiddleware(req as any, res as any, (err) => {
      if (err) return next(err);
      csrfCookieSetter(req as any, res as any, next);
    });
  });

  // Reject cross-site state-changing requests whose Origin does not match the
  // configured frontend origin. This is defense-in-depth alongside CSRF tokens.
  app.use((req, res, next) => {
    if (safeMethods.has(req.method.toUpperCase())) return next();
    const origin = req.headers.origin;
    if (origin && origin !== frontendUrl) {
      return res.status(403).json({ message: 'Cross-site request blocked' });
    }
    return next();
  });
  app.setGlobalPrefix('api');

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  app.useGlobalFilters(
    new AllExceptionsFilter(),
    new HttpExceptionFilter(),
    new ThrottlerExceptionFilter(),
  );

  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('xConfess API')
      .setDescription(
        'Anonymous confession platform API — confessions, reactions, messages, reports, admin, and Stellar integration.',
      )
      .setVersion('1.0')
      .addBearerAuth()
      .addTag('Auth', 'Authentication endpoints')
      .addTag('Users', 'User registration, profile, and settings')
      .addTag(
        'Confessions',
        'Confession CRUD, search, tags, and Stellar anchoring',
      )
      .addTag('Comments', 'Comment CRUD and moderation')
      .addTag('Reactions', 'Emoji reactions on confessions')
      .addTag('Messages', 'Anonymous messaging between users')
      .addTag('Reports', 'Report creation and moderation')
      .addTag('Admin', 'Admin dashboard and RBAC operations')
      .addTag('Admin - Moderation', 'AI moderation review and configuration')
      .addTag('Admin - Comments', 'Admin comment approval and rejection')
      .addTag('Analytics', 'Platform analytics and trending')
      .addTag('Tipping', 'XLM micro-tipping on Stellar')
      .addTag('Stellar', 'Stellar blockchain integration')
      .addTag('Health', 'Health check endpoints')
      .addTag('Data Export', 'GDPR data export and download')
      .addTag('Search Discovery', 'Saved searches and search history')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  const port = configService.get<number>('app.port', 3000);
  await app.listen(port);

  // ── Startup Summary ──────────────────────────────────────────────────────────
  const logger = app.get(AppLogger);
  const env = configService.get<string>('NODE_ENV', 'development');
  const dbHost = configService.get<string>('DB_HOST', 'localhost');
  const dbPort = configService.get<number>('DB_PORT', 55432);
  const redisHost = configService.get<string>('REDIS_HOST', 'localhost');
  const redisPort = configService.get<number>('REDIS_PORT', 6379);
  const backgroundJobMode = configService.get<string>('ENABLE_BACKGROUND_JOBS', 'false');
  
  logger.log(
    `🚂 Application started successfully`,
    'Bootstrap'
  );
  logger.log(
    `Environment: ${env} | Port: ${port} | DB: ${dbHost}:${dbPort} | Redis: ${redisHost}:${redisPort} | Background Jobs: ${backgroundJobMode}`,
    'Bootstrap'
  );
  logger.log(
    `CSP: ${cspPolicy.mode} | Report URI: ${cspPolicy.reportUri ?? 'n/a'}`,
    'Bootstrap'
  );
}
bootstrap();
