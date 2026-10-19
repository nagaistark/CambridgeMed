import '@ssot/date_time_constants.ts';
import express, {
   type Express,
   type Request,
   type Response,
   type NextFunction,
} from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit, { type Options } from 'express-rate-limit';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';

import { myEnv } from './validateConfig.ts';
import logger from './logger.ts';

import cookieParser from 'cookie-parser';

import authRouter from '@auth/auth.routes.ts';
import inviteRouter from '@invites/invites.routes.ts';
import usersRouter from '@users/users.routes.ts';
import sessionsRouter from '@sessions/sessions.routes.ts';
import patientRouter from '@patients/patients.routes.ts';

import { DatabaseManager } from './mongoDBConnect.ts';

import {
   handleParseError,
   handleEffectFailure,
   handleMongoDbError,
   handleJwtError,
   handleHttpError,
   handleEnoentError,
   handleCatchAll,
   createErrorResponse,
} from './errorHandlers.ts';

import { DateTime } from 'luxon';
import {
   FALLBACK_HEX_SECRET_PATTERN,
   SENSITIVE_URL_PARAM_NAMES,
} from '@ssot/logging_constants.ts';
import { escapeRegex } from './utils/escapeRegex.ts';
import { requireTrustedOrigin } from './middleware/requireTrustedOrigin.ts';

// ===== APP INITIALIZATION & CONFIG ===============================================
const app: Express = express();

// Render/Railway/Docker: telling Express it's behind a proxy
app.set('trust proxy', 1);

// That annoying __dirname workaround
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== MIDDLEWARE PIPELINE =======================================================
/* A. Request ID must be first so that all subsequent logs can reference it */
app.use((_req: Request, res: Response, next: NextFunction) => {
   const requestId = randomUUID();
   res.locals['requestId'] = requestId; // internal scratchpad
   res.setHeader('X-Request-Id', requestId); // sent back to the client
   next();
});

/* B. Morgan config. Registering the token once, before the Morgan middleware */
morgan.token('safe-url', (req: Request): string => {
   let url = req.originalUrl;

   /* Layer 1 — precise: redact by known route-param identity. */
   for (const paramName of SENSITIVE_URL_PARAM_NAMES) {
      const value = req.params[paramName];
      if (typeof value === 'string' && value.length > 0) {
         url = url.replace(new RegExp(escapeRegex(value), 'g'), '[REDACTED]');
      }
   }

   /* Layer 2 — safety net: anything token-shaped that layer 1 missed (unmatched routes, future token types nobody registered above). */
   return url.replace(FALLBACK_HEX_SECRET_PATTERN, '[REDACTED]');
});

const morganFormat =
   process.env.NODE_ENV === 'production'
      ? ':request-id :remote-addr :method :safe-url :status :res[content-length] - :response-time ms'
      : ':request-id :method :safe-url :status :response-time ms';

app.use(
   morgan(morganFormat, {
      stream: {
         write: (message: string) => logger.http(message.trimEnd()),
      },
   })
);

// C. CORS (Placeholder for now. We'll work on it later...)
const corsOptions: cors.CorsOptions = {
   origin: [...myEnv.cors.origins], // spread: `cors` wants a mutable array
   methods: ['GET', 'POST', 'PATCH', 'DELETE'],
   allowedHeaders: ['Content-Type'],
   exposedHeaders: ['X-Request-Id'],
   credentials: true,
   maxAge: 600,
   optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

// D. Security headers
app.use(
   helmet({
      frameguard: { action: 'deny' },
      contentSecurityPolicy: {
         directives: {
            defaultSrc: ["'self'"], // Everything defaults to same-origin only
            scriptSrc: ["'self'"], // JavaScript: same-origin only
            styleSrc: ["'self'", 'https://fonts.googleapis.com'], // CSS: same-origin only + Google Fonts
            imgSrc: ["'self'", 'data:'], // Images: same-origin + inline data URIs
            connectSrc: ["'self'"], // Fetch/XHR: same-origin only
            fontSrc: ["'self'", 'https://fonts.gstatic.com'], // Fonts: same-origin only + Google Fonts
            objectSrc: ["'none'"], // No plugins (Flash etc.) ever
            frameAncestors: ["'none'"], // Nobody can iframe this site
            upgradeInsecureRequests: [], // Auto-upgrade HTTP to HTTPS
         },
      },
   })
);

// E. Never cache API responses (tokens, PHI-adjacent data).
app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
   res.setHeader('Cache-Control', 'no-store');
   res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=()'
   );
   next();
});

// F. CSRF defence-in-depth: rejects state-changing requests from untrusted origins before any parsing or rate-limiting.
app.use('/api', requireTrustedOrigin);

// G. Rate limiting
const limiter = rateLimit({
   windowMs: 15 * 60 * 1000,
   limit: 100,
   standardHeaders: 'draft-8',
   legacyHeaders: false,
   ipv6Subnet: 56, // treating /56 IPv6 subnets as one identity
   handler: (
      _req: Request,
      res: Response,
      _next: NextFunction,
      options: Options
   ) => {
      const requestId = res.locals['requestId'];
      res.status(options.statusCode).json(
         createErrorResponse(
            'RATE_LIMITED',
            'Too many requests from this IP, please try again later',
            requestId
         )
      );
   },
});

// General API protection
app.use('/api', limiter);

// H. Body Parsers & Static Files
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// I. Cookie parser (AFTER Body Parsers, BEFORE Routes!) Required for req.cookies to be populated (logout reads the refresh token cookie).
app.use(cookieParser());

// ===== ROUTES ====================================================================
app.get('/health', limiter, (_req: Request, res: Response) => {
   const dbManager = DatabaseManager.getInstance();
   const authReady = dbManager.auth.isConnected;
   const clinicReady = dbManager.clinic.isConnected;
   const healthy = authReady && clinicReady;

   res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'degraded',
      uptime: process.uptime(),
      databases: {
         auth: authReady,
         clinic: clinicReady,
      },
   });
});
// Simple route example. No reason.
app.get(/^\/$|\/index(.html)?$/, (_req: Request, res: Response) => {
   const now = DateTime.now();
   logger.debug(`${now.toString()} — ${now.zoneName}`);
   res.send('<h1>Welcome to CambridgeMed, Ontario!</h1>');
});

// To the future me! Auth domain should be mounted BEFORE the catch-all 404 handlers
app.use('/api/auth', authRouter);
app.use('/api/invites', inviteRouter);
app.use('/api/users', usersRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/patients', patientRouter);

// ===== 404 & GLOBAL ERROR HANDLING (Must be last!) ===============================
/* Tier 1. API routes that don't exist → proper JSON 404 */
app.use('/api/*splat', (req: Request, res: Response) => {
   const requestId = res.locals['requestId'];
   res.status(404).json(
      createErrorResponse(
         'NOT_FOUND',
         `API route ${req.originalUrl.replace(FALLBACK_HEX_SECRET_PATTERN, '[REDACTED]')} not found.`,
         requestId
      )
   );
});

/* Tier 2. Everything else (GET only) → serve React's index.html */
app.get('/{*splat}', (_req: Request, res: Response) => {
   res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handlers (order is critical → most specific first, catch-all last) ──
app.use(handleEffectFailure); // 1. Unwrap FiberFailure first — everything below assumes bare errors
app.use(handleParseError); // 2. Effect Schema validation failures
app.use(handleMongoDbError); // 3. MongoDB errors
app.use(handleJwtError); // 4. jose JWT errors
app.use(handleHttpError); // 5. Known HTTP errors (status/statusCode)
app.use(handleEnoentError); // 6. Filesystem errors from sendFile
app.use(handleCatchAll); // 7. Catch-All (must always come last)

export default app;
