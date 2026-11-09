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

import { FALLBACK_HEX_SECRET_PATTERN } from '@ssot/logging_constants.ts';
import { requireTrustedOrigin } from '@middleware/requireTrustedOrigin.ts';
import { isShuttingDown } from './shutdown.ts';
import { globalApiRateLimiter } from '@utils/rateLimiters.ts';

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
   const [pathOnly = ''] = req.originalUrl.split('?');
   return pathOnly.replace(FALLBACK_HEX_SECRET_PATTERN, '[REDACTED]');
});

const morganFormat: morgan.FormatFn<Request, Response> = (tokens, req, res) =>
   [
      res.locals.requestId,
      myEnv.environment === 'production' ? req.ip : undefined,
      req.method,
      tokens['safe-url'](req, res),
      tokens.status(req, res),
      tokens['response-time'](req, res),
      'ms',
   ]
      .filter(part => part !== undefined)
      .join(' ');

app.use(
   morgan(morganFormat, {
      stream: {
         write: (message: string) => logger.http(message.trimEnd()),
      },
      /* Successful health probes are noise (the platform polls constantly); failures (>= 400) are still logged. */
      skip: (req, res) => req.path === '/health' && res.statusCode < 400,
   })
);

// C. CORS (Placeholder for now. We'll work on it later...)
const corsOptions: cors.CorsOptions = {
   origin: [...myEnv.cors.origins], // spread: `cors` wants a mutable array
   methods: ['GET', 'POST', 'PATCH', 'DELETE'],
   allowedHeaders: ['Content-Type'],
   exposedHeaders: [
      'X-Request-Id',
      'RateLimit',
      'RateLimit-Policy',
      'Retry-After',
   ],
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
            upgradeInsecureRequests:
               myEnv.environment === 'production' ? [] : null, // Auto-upgrade HTTP to HTTPS
         },
      },
   })
);

// D2. Permissions-Policy matters on HTML documents, so it must not be scoped to /api only.
app.use((_req: Request, res: Response, next: NextFunction) => {
   res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=()'
   );
   next();
});

// E. Never cache API responses (tokens, PHI-adjacent data).
app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
   res.setHeader('Cache-Control', 'no-store');
   next();
});

// F. CSRF defence-in-depth: rejects state-changing requests from untrusted origins before any parsing or rate-limiting.
app.use('/api', requireTrustedOrigin);

// G. General API protection
app.use('/api', globalApiRateLimiter);

// H. Body Parsers & Static Files
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// I. Cookie parser (AFTER Body Parsers, BEFORE Routes!) Required for req.cookies to be populated (logout reads the refresh token cookie).
app.use(cookieParser());

// ===== ROUTES ====================================================================
app.get('/health', globalApiRateLimiter, (_req: Request, res: Response) => {
   const databases = DatabaseManager.getInstance();
   const healthy =
      !isShuttingDown() &&
      databases.auth.isConnected &&
      databases.clinic.isConnected &&
      databases.audit.isConnected;

   /* Public endpoint: status only. No uptime, no per-database breakdown. */
   res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'degraded',
   });
});

// To the future me! Auth domain should be mounted BEFORE the catch-all 404 handlers
app.use('/api/auth', authRouter);
app.use('/api/invites', inviteRouter);
app.use('/api/users', usersRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/patients', patientRouter);

// ===== 404 & GLOBAL ERROR HANDLING (Must be last!) ===============================
/* Tier 1. API routes that don't exist → proper JSON 404 */
app.use('/api', (_req: Request, res: Response) => {
   return void res
      .status(404)
      .json(
         createErrorResponse(
            'NOT_FOUND',
            `API route not found.`,
            res.locals.requestId
         )
      );
});

const FILE_EXTENSION_PATTERN = /\.[a-z0-9]+$/i;

app.get('/{*splat}', (req: Request, res: Response, next: NextFunction) => {
   if (FILE_EXTENSION_PATTERN.test(req.path)) return next(); // real 404 for missing assets
   res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((_req: Request, res: Response) => {
   return void res
      .status(404)
      .json(
         createErrorResponse('NOT_FOUND', `Not found.`, res.locals.requestId)
      );
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
