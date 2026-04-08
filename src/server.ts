import '@ssot/date_time_constants.ts';
import express, { Express, Request, Response, NextFunction } from 'express';
import { Server } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit, { Options } from 'express-rate-limit';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';

import { myEnv } from 'validateConfig.ts';
import { validateJwtKeys } from '@utils/jwtUtils.ts';
import logger from 'logger.ts';

import cookieParser from 'cookie-parser';

import authRouter from '@auth/auth.routes.ts';
import inviteRouter from '@invites/invite.routes.ts';

import {
   DatabaseManager,
   handleGracefulShutdown,
   sanitizeError,
} from 'dbConnect.ts';

import {
   handleValiError,
   handleMongooseError,
   handleJwtError,
   handleHttpError,
   handleEnoentError,
   handleCatchAll,
   createErrorResponse,
} from 'errorHandlers.ts';

import { DateTime } from 'luxon';

// ====================================================================================
// 1. GLOBAL PROCESS LISTENERS (Must be first!)
// ====================================================================================
process.on('uncaughtException', (error: Error) => {
   const sanitized = sanitizeError(error);
   logger.error(
      `Uncaught Exception! Critical failure:\n${sanitized.message}\n${sanitized.stack}`
   );
   process.exit(1);
});

process.on('unhandledRejection', (reason: unknown) => {
   // Normalizing to an Error so that the `uncaughtException` handler always gets a proper stack
   const error =
      reason instanceof Error
         ? reason
         : new Error(`Unhandled Rejection: ${String(reason)}`);
   logger.error(`Unhandled Rejection:\n${error.stack}`);
   throw error;
});

// ====================================================================================
// 2. APP INITIALIZATION & CONFIG
// ====================================================================================
const app: Express = express();
const port: number = myEnv.server.port;
const host: string = myEnv.server.host;

// Render/Railway/Docker: telling Express it's behind a proxy
app.set('trust proxy', 1);

// That annoying __dirname workaround
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====================================================================================
// 3. MIDDLEWARE PIPELINE
// ====================================================================================
// A. Request ID must be first so that all subsequent logs can reference it
app.use((_req: Request, res: Response, next: NextFunction) => {
   const requestId = randomUUID();
   res.locals['requestId'] = requestId; // internal scratchpad ✓
   res.setHeader('X-Request-Id', requestId); // sent back to the client ✓
   next();
});

// B. Morgan config
// Registering the token once, before the Morgan middleware
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
   origin: myEnv.cors.origins,

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
            undefined,
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
            undefined,
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

// ====================================================================================
// 4. ROUTES
// ====================================================================================
app.get('/health', limiter, (_req: Request, res: Response) => {
   const dbManager = DatabaseManager.getInstance();
   const authReady = dbManager.auth.connection?.readyState === 1;
   const clinicReady = dbManager.clinic.connection?.readyState === 1;
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

// ====================================================================================
// 5. 404 & GLOBAL ERROR HANDLING (Must be last!)
// ====================================================================================
// Tier 1. API routes that don't exist → proper JSON 404
app.use('/api/*splat', (req: Request, res: Response) => {
   const requestId = res.locals['requestId'];
   res.status(404).json(
      createErrorResponse(
         'NOT_FOUND',
         `API route ${req.originalUrl} not found.`,
         undefined,
         requestId
      )
   );
});

// Tier 2. Everything else → serve React's index.html
app.use('/{*splat}', (req: Request, res: Response) => {
   res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handlers (order is critical → most specific first, catch-all last) ──
app.use(handleValiError); // 1. Valibot schema failures
app.use(handleMongooseError); // 2. Mongoose / MongoDB errors
app.use(handleJwtError); // 3. jose JWT errors
app.use(handleHttpError); // 4. Known HTTP errors (status/statusCode)
app.use(handleEnoentError); // 5. Filesystem errors from sendFile
app.use(handleCatchAll); // 6. Catch-All (must always come last)

// ====================================================================================
// 6. SERVER BOOTSTRAP
// The order of operations:
//   Step 1 — JWT keys:  pure memory, instant, cheap to check
//   Step 2 — Database:  network I/O, slow, pointless if Step 1 failed
//   Step 3 — HTTP server: no point listening for requests until Steps 1 & 2 pass
// ====================================================================================
let server!: Server;

const startServer = async (): Promise<void> => {
   try {
      logger.info(`Starting server bootstrap...`);

      // Step 1: Validating JWT key pair
      logger.info(`Validating JWT key pair...`);
      await validateJwtKeys();
      logger.info(`JWT key pair validated successfully`);

      // Step 2: Connecting to the database
      const dbManager = DatabaseManager.getInstance();
      await dbManager.initialize();

      // Step 3: Starting the HTTP server
      server = await new Promise<Server>((resolve, reject) => {
         const s = app.listen(port, host, () => resolve(s));
         s.once('error', reject);
      });

      // Set immediately after listen, before any connection arrive
      server.keepAliveTimeout = 80_000; // Must exceed Render's timeout value
      server.headersTimeout = 81_000; // Must exceed keepAliveTimeout
      server.requestTimeout = 30_000; // Kills the socket if the full incoming request (headers + body) isn't received within 30s. Our defence against against Slowloris-style attacks.
      server.timeout = 0; // Disabling the legacy socket inactivity timer...

      logger.info(`Server running at http://${host}:${port}`);
      logger.info(`Keep-alive timeout: ${server.keepAliveTimeout}ms`);
   } catch (error) {
      // All three steps funnel into single `catch` block.
      const sanitized = sanitizeError(error);
      logger.error(`Fatal startup error: ${sanitized.stack}`);

      // Calling `cleanup` is safe even if the DB never connected.
      await DatabaseManager.getInstance().cleanup();
      process.exit(1);
   }
};

const onShutdownSignal = (signal: 'SIGINT' | 'SIGTERM') => {
   if (!server) {
      logger.warn(
         `${signal} received during startup. Cleaning up and exiting.`
      );
      DatabaseManager.getInstance()
         .cleanup()
         .then(() => process.exit(0))
         .catch(() => process.exit(1));
      return;
   }
   handleGracefulShutdown(server, signal);
};

process.once('SIGINT', () => onShutdownSignal('SIGINT'));
process.once('SIGTERM', () => onShutdownSignal('SIGTERM'));

startServer();
