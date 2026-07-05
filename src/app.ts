import '@ssot/date_time_constants.ts';
import express, { Express, Request, Response, NextFunction } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit, { Options } from 'express-rate-limit';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';

import { myEnv } from 'validateConfig.ts';
import logger from 'logger.ts';

import cookieParser from 'cookie-parser';

import authRouter from '@auth/auth.routes.ts';
import inviteRouter from '@invites/invites.routes.ts';
import usersRouter from '@users/users.routes.ts';
import sessionsRouter from '@sessions/sessions.routes.ts';
import patientRouter from '@patients/patients.routes.ts';

import { DatabaseManager } from 'mongoDBConnect.ts';

import {
   handleParseError,
   handleEffectFailure,
   handleMongoDbError,
   handleJwtError,
   handleHttpError,
   handleEnoentError,
   handleCatchAll,
   createErrorResponse,
} from 'errorHandlers.ts';

import { DateTime } from 'luxon';

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

/* B. Morgan config
   Registering the token once, before the Morgan middleware */
morgan.token('request-id', (_req: Request, res: Response): string => {
   return res.locals['requestId'] ?? 'unknown';
});
// Including it in a custom format string
const morganFormat =
   process.env.NODE_ENV === 'production'
      ? ':request-id :remote-addr :method :url :status :res[content-length] - :response-time ms'
      : ':request-id :method :url :status :response-time ms';

app.use(
   morgan(morganFormat, {
      stream: {
         write: (message: string) => logger.http(message.trimEnd()),
      },
   })
);

// C. CORS (Placeholder for now. We'll work on it later...)
const corsOptions: cors.CorsOptions = {
   /* `origin` is the heart of the config. We pass our array of allowed origins directly from the validated environment. The cors package will do a strict string equality check against the incoming Origin header. */
   origin: [...myEnv.cors.origins],

   /* Explicitly whitelist the HTTP methods your API actually uses. OPTIONS must be included here to allow preflight requests through. "Deny by default, allow by exception" — don't leave this as the open default. */
   methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

   /* Headers our frontend is allowed to send:
   • Content-Type covers JSON bodies.
   • Authorization covers Bearer tokens (for when we add auth later).
   • X-Request-Id is our custom correlation header — allowing it means our frontend could theoretically send its own request ID, which we may want for end-to-end tracing. */
   allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],

   /* Headers the browser is allowed to *read* from the response. By default, browsers can only access a small set of "safe" headers. Exposing X-Request-Id means our frontend JS can read the correlation ID from responses — very useful for displaying to users when reporting errors. */
   exposedHeaders: ['X-Request-Id'],

   /* This is the big one for auth. Setting credentials: true tells the browser it's allowed to send cookies and Authorization headers cross-origin. CRITICAL: when this is true, we CANNOT use a wildcard (*) for origin */
   credentials: true,

   /* How long (in seconds) the browser can cache a preflight response. 600 = 10 minutes. This reduces the number of OPTIONS round-trips our frontend makes, which speeds up perceived API performance. */
   maxAge: 600,

   /* Ensures the CORS headers are set on error responses too, not just 200s. Without this, if our server returns a 401 or 500, the browser might suppress the response entirely due to missing CORS headers, making debugging very confusing. */
   preflightContinue: false,
   optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

// D. Security headers
app.use(
   helmet({
      frameguard: false, // Intentionally disabled. CSP frameAncestors: 'none' covers this for modern browsers
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

// E. Rate limiting
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

const authLimiter = rateLimit({
   windowMs: 15 * 60 * 1000,
   limit: 10,
   standardHeaders: 'draft-8',
   legacyHeaders: false,
   skipSuccessfulRequests: true, // A correct password doesn't consume the quota
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
            'Too many login attempts. Please wait 15 minutes before trying again.',
            requestId
         )
      );
   },
});

// General API protection
app.use('/api', limiter);

// Stricter limit on login to prevent brute-force attacks
app.use('/api/auth/login', authLimiter);

// F. Body Parsers & Static Files
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// G. Cookie parser (AFTER Body Parsers, BEFORE Routes!) Required for req.cookies to be populated (logout reads the refresh token cookie).
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
   logger.debug(`${DateTime.now()} — ${DateTime.now().zoneName}`);
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
         `API route ${req.originalUrl} not found.`,
         requestId
      )
   );
});

/* Tier 2. Everything else → serve React's index.html */
app.use('/{*splat}', (req: Request, res: Response) => {
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
