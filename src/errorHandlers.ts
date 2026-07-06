import type { Request, Response, NextFunction } from 'express';
import { ParseResult, Runtime, Cause } from 'effect';
import { MongoError, MongoNetworkError, MongoServerError } from 'mongodb';
import { errors as joseErrors } from 'jose';
import logger from 'logger.ts';

// ===== Every possible machine-readable error code (so far) =======================
export type ErrorCode =
   // ───── Client errors (4XX) ────────────────────────────────────────────────────
   | 'VALIDATION_ERROR' // Valibot ValiError: body/params failed schema validation
   | 'INVALID_JSON' // Body parser couldn't parse the request body as JSON
   | 'NOT_FOUND' // Route or database document does not exist
   | 'METHOD_NOT_ALLOWED' // Valid route, but wrong HTTP verb
   | 'CONFLICT' // Uniqueness violation (e.g. duplicate email) — MongoDB 11000
   // ── Auth errors (401/403) ────────────────────────────────────────────
   | 'UNAUTHORIZED' // No credentials provided — "I don't know who you are"
   | 'FORBIDDEN' // Valid credentials, insufficient permissions — "No means no"
   // ── Rate limiting (429) ──────────────────────────────────────────────
   | 'RATE_LIMITED' // express-rate-limit triggered — tell client to back off
   // ── Server/operational errors (5XX) ──────────────────────────────────
   | 'SERVICE_UNAVAILABLE' // Known infrastructure failure: bad deploy, DB unreachable
   | 'DATABASE_ERROR' // MongoDB runtime error not caused by client input
   // ── Catch-all (500) ──────────────────────────────────────────────────
   | 'INTERNAL_ERROR'; // Unexpected programmer error — details hidden in production

const VALID_ERROR_CODES = new Set<ErrorCode>([
   'VALIDATION_ERROR',
   'INVALID_JSON',
   'NOT_FOUND',
   'METHOD_NOT_ALLOWED',
   'CONFLICT',
   'UNAUTHORIZED',
   'FORBIDDEN',
   'RATE_LIMITED',
   'SERVICE_UNAVAILABLE',
   'DATABASE_ERROR',
   'INTERNAL_ERROR',
]);

// ===== CANONICAL RESPONSE SHAPE ==================================================
interface ApiErrorResponse {
   success: false; // It's always literally "false" for Errors, not just "boolean"
   code: string;
   message: string;
   details?: unknown;
   requestId?: string;
}

// ===== FACTORY FUNCTION that produces a guaranteed-valid ApiErrorResponse ========
export function createErrorResponse(
   // `code` must be one of the strings in our `ErrorCode` union
   code: ErrorCode,

   // A human-readable message safe to display. The handler is responsible for deciding whether this should be vague (production) or candid (dev).
   message: string,

   // The correlation ID from res.locals.requestId, also optional because in some edge cases (very early middleware failures) it may not exist yet.
   requestId: string,

   // `details` is optional — only Valibot field-level issues and similar structured payloads will use this. `unknown` forces any consumer of this field to narrow its type before using it, which is the safe choice.
   details?: unknown
): ApiErrorResponse {
   if (details !== undefined) {
      return {
         success: false,
         code,
         message,
         requestId,
         details,
      };
   }
   return {
      success: false,
      code,
      message,
      requestId,
   };
}

// ===== The expected shapes of HTTP-like errors ===================================
// Express Body Parser (e.g., malformed JSON)
interface BodyParserError extends Error {
   status: number;
   type: string; // will be 'entity.parse.failed' for bad JSON
}

// http-errors package — used by Express internally and by many auth libraries.
interface HttpCreatedError extends Error {
   status: number;
   statusCode: number;
   expose: boolean;
}

// The broadest fallback: something manually thrown in a route handler with just a `status` property attached — no `statusCode`, no `expose`.
interface StatusOnlyError extends Error {
   status: number;
}

// Same but using `statusCode` instead of `status` — some older middleware follows Node's http module convention instead of Express's convention.
interface StatusCodeOnlyError extends Error {
   statusCode: number;
}

// The union of all four
export type HttpErrorLike =
   | BodyParserError
   | HttpCreatedError
   | StatusOnlyError
   | StatusCodeOnlyError;

// ===== Type guards for Http-related errors =======================================
/* Body parser error: has `status` AND `type`, but not `expose`. We check `type` as a string but wait until the handler to compare it to 'entity.parse.failed' — the guard's job is existence and type, not value. */
function isBodyParserError(err: unknown): err is BodyParserError {
   return (
      err instanceof Error &&
      'status' in err &&
      typeof (err as Record<string, unknown>)['status'] === 'number' &&
      'type' in err &&
      typeof (err as Record<string, unknown>)['type'] === 'string'
   );
}

/* http-errors error: has all three — status, statusCode, AND expose. The presence of `expose` as a boolean is the unique fingerprint here. */
function isHttpCreatedError(err: unknown): err is HttpCreatedError {
   return (
      err instanceof Error &&
      'status' in err &&
      typeof (err as Record<string, unknown>)['status'] === 'number' &&
      'statusCode' in err &&
      typeof (err as Record<string, unknown>)['statusCode'] === 'number' &&
      'expose' in err &&
      typeof (err as Record<string, unknown>)['expose'] === 'boolean'
   );
}

/* Generic status-only: has `status` as a number, but nothing else specific. */
function isStatusOnlyError(err: unknown): err is StatusOnlyError {
   return (
      err instanceof Error &&
      'status' in err &&
      typeof (err as Record<string, unknown>)['status'] === 'number'
   );
}

/* Generic statusCode-only: same but using the Node http module convention. */
function isStatusCodeOnlyError(err: unknown): err is StatusCodeOnlyError {
   return (
      err instanceof Error &&
      'statusCode' in err &&
      typeof (err as Record<string, unknown>)['statusCode'] === 'number'
   );
}

/* Mapping an HTTP status code to the ErrorCode union. The `type` parameter carries the body-parser's `entity.parse.failed` marker, which is the only reliable way to distinguish "bad JSON" (INVALID_JSON) from a generic "bad request" (VALIDATION_ERROR) at the 400 level. */
const statusToErrorCode = (status: number, type?: string): ErrorCode => {
   if (status === 400 && type === 'entity.parse.failed') return 'INVALID_JSON';
   if (status === 400) return 'VALIDATION_ERROR';
   if (status === 401) return 'UNAUTHORIZED';
   if (status === 403) return 'FORBIDDEN';
   if (status === 404) return 'NOT_FOUND';
   if (status === 405) return 'METHOD_NOT_ALLOWED';
   if (status === 409) return 'CONFLICT';
   if (status === 429) return 'RATE_LIMITED';
   // Anything in the 5XX range that made it here is an unexpected server failure.
   return 'INTERNAL_ERROR';
};

// ===== OPERATIONAL ERRORS VS PROGRAMMER ERRORS ===================================
/* A best-effort heuristic for distinguishing operational errors from programmer errors. We recognise known Node.js operational error classes by name, since they don't share a common base class we can use instanceof with. This list covers the most common cases — it is intentionally conservative. When in doubt, we treat an error as a programmer error (the safer assumption, because it triggers more aggressive logging and a 500 rather than a 503). */
const OPERATIONAL_ERROR_NAMES = new Set([
   'ErrnoException', // Node.js filesystem and OS-level errors
   'ECONNREFUSED', // Connection refused by remote host
   'ECONNRESET', // Connection reset mid-transfer
   'ETIMEDOUT', // Operation timed out
   'ENOTFOUND', // DNS lookup failure
]);

function isOperationalError(err: unknown): boolean {
   if (!(err instanceof Error)) return false;

   /* Check the error's name property against our known operational error names. We also check err.code for ErrnoException variants, because Node's filesystem errors often carry the POSIX code ('ENOENT', 'EACCES', etc.) as `err.code` rather than as `err.name`. */
   const code = (err as NodeJS.ErrnoException).code;
   return (
      OPERATIONAL_ERROR_NAMES.has(err.name) ||
      (typeof code === 'string' && OPERATIONAL_ERROR_NAMES.has(code))
   );
}

// ===== "SPECIALISTS" in the pipeline. Each only touches the errors it recognizes =

// ===== The Effect Schema validation specialist/handler ===========================
export function handleParseError(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   // If this isn't a ParseError, it's not our job. Passing it to the next "specialist".
   if (!ParseResult.isParseError(err)) return next(err);

   const requestId = res.locals.requestId;

   /* ArrayFormatter gives back only { _tag, path, message } per issue — same structural shape as the old { path, message } we built from ValiError. path is a ReadonlyArray<PropertyKey>, so String(...) covers string/number/symbol keys uniformly, matching the original's String(p.key). */
   const details = ParseResult.ArrayFormatter.formatErrorSync(err).map(
      issue => ({
         path: issue.path.map(String),
         message: issue.message,
      })
   );

   return void res
      .status(422)
      .json(
         createErrorResponse(
            'VALIDATION_ERROR',
            `The request data failed validation.`,
            requestId,
            details
         )
      );
}

// ===== The Effect tagged-error specialist/handler ================================
/* The generic contract any custom domain error must satisfy to be automatically converted into an HTTP response here. Nothing Effect-specific about the shape itself — pairing `status`/`code` directly on the error is what lets this ONE specialist handle every current and future tagged error without this file ever needing to know their names. Define your errors like:
   class NotFoundError extends Data.TaggedError('NotFoundError')<{
      message: string;
      status: number;
      code: 'NOT_FOUND';
   }> {}

...and either `throw new NotFoundError({...})` directly in a plain async handler, or `Effect.fail(new NotFoundError({...}))` inside an Effect program — both are recognized below. */
interface AppErrorShape {
   readonly _tag: string;
   readonly status: number;
   readonly code: ErrorCode;
}

function isAppError(value: unknown): value is Error & AppErrorShape {
   if (!(value instanceof Error)) return false;
   if (!('_tag' in value) || typeof value._tag !== 'string') return false;
   if (!('status' in value) || typeof value.status !== 'number') return false;
   if (!('code' in value) || typeof value.code !== 'string') return false;
   return VALID_ERROR_CODES.has(value.code as never) === false ? false : true;
}

export function handleEffectFailure(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   const requestId = res.locals.requestId;

   /* Case 1: the error escaped Effect.runPromise/runFork, wrapped in a FiberFailure. */
   if (Runtime.isFiberFailure(err)) {
      const cause = err[Runtime.FiberFailureCauseId];

      /* Cause.isFailType narrows to "this was an Effect.fail(...), a value the program's error TYPE explicitly declared" — as opposed to a Die (an uncaught throw / defect) or an Interrupt. Only Fail values are safe to treat as expected, application-level errors. A Die means a bug escaped from inside an Effect program; even if it happens to look like one of our tagged errors, it wasn't declared through Effect.fail and must NOT be short-circuited into a clean response — it needs the full stack-trace treatment from the catch-all. */
      if (!Cause.isFailType(cause)) {
         /* Squash to recover the REAL underlying defect (not Effect's synthetic wrapper) so downstream logging shows the true stack trace. */
         return next(Cause.squash(cause));
      }

      const squashed = Cause.squash(cause);

      if (isAppError(squashed)) {
         return void res
            .status(squashed.status)
            .json(
               createErrorResponse(squashed.code, squashed.message, requestId)
            );
      }

      /* A typed failure we don't have a convention for yet (e.g. a bare ParseError from Schema.decodeUnknown used inside an Effect program) — decline, forward the unwrapped value to the next specialist. */
      return next(squashed);
   }

   /* Case 2: a tagged error thrown directly, no Effect runtime involved at all. */
   if (isAppError(err)) {
      return void res
         .status(err.status)
         .json(createErrorResponse(err.code, err.message, requestId));
   }

   /* Not ours — not a FiberFailure, not a recognized tagged error. */
   return next(err);
}

// ===== The MongoDB specialist/handler ============================================
export function handleMongoDbError(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   /* Pull the correlation ID once, at the top, so every branch below can use it without repeating the same res.locals lookup.
   res.locals is typed as Record<string, any> by Express, so we narrow it manually rather than letting `any` silently propagate. */
   const requestId = res.locals.requestId;

   // ── MongoNetworkError ─────────────────────────────────────────────────────────
   /* This is a driver-level error: the connection to the database was lost mid-request. It has nothing to do with the client's data — it's a pure infrastructure failure. 503 tells the client "try again later."*/
   if (err instanceof MongoNetworkError) {
      return void res
         .status(503)
         .json(
            createErrorResponse(
               'SERVICE_UNAVAILABLE',
               `A database connectivity issue occurred. Please try again shortly.`,
               requestId
            )
         );
   }

   // ── Duplicate key error (MongoDB code 11000) ──────────────────────────────────
   /* This is also a driver-level error, but caused by client data: the user tried to insert a value that violates a unique index (e.g. an email address that already exists). We check `instanceof MongoServerError` first to confirm it's from the right class before trusting `err.code`, since other objects in JavaScript can also happen to have a `code` property. We deliberately do NOT include err.keyValue in the response because it contains the exact duplicate value the user tried to insert. */
   if (err instanceof MongoServerError && err.code === 11000) {
      return void res
         .status(409)
         .json(
            createErrorResponse(
               'CONFLICT',
               `A record with that value already exists.`,
               requestId
            )
         );
   }

   // Broad catch-all for any other driver-level error we didn't anticipate.
   if (err instanceof MongoError) {
      return void res
         .status(500)
         .json(
            createErrorResponse(
               'DATABASE_ERROR',
               'An unexpected database error occurred.',
               requestId
            )
         );
   }

   // ── Not our responsibility ────────────────────────────────────────────────────
   /* This error isn't MongoDB related. Pass it to the next specialist in the pipeline without touching it. */
   return next(err);
}

// ===== The JWT specialist/handler ================================================
export function handleJwtError(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   // If the error isn't from JOSE, pass it along.
   if (!(err instanceof joseErrors.JOSEError)) return next(err);

   const requestId = res.locals.requestId;

   /* JWTExpired is a NORMAL, EXPECTED lifecycle event — the access token ran out and the client needs to hit /api/auth/refresh. */
   if (err instanceof joseErrors.JWTExpired) {
      return void res
         .status(401)
         .json(
            createErrorResponse('UNAUTHORIZED', 'Token has expired.', requestId)
         );
   }

   /* Everything else — forged signatures, malformed tokens, invalid claims, wrong algorithm — gets a DELIBERATELY VAGUE message because a specific message would only benefit an attacker probing our system. */
   return void res
      .status(401)
      .json(
         createErrorResponse(
            'UNAUTHORIZED',
            'Invalid or malformed token.',
            requestId
         )
      );
}

// ===== The HTTP specialist/handler ===============================================
export function handleHttpError(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   const requestId = res.locals.requestId;

   // Most specific first: body parser error
   if (isBodyParserError(err)) {
      const code =
         err.type === 'entity.parse.failed'
            ? 'INVALID_JSON'
            : 'VALIDATION_ERROR';

      return void res
         .status(err.status)
         .json(
            createErrorResponse(
               code,
               'The request body could not be parsed.',
               requestId
            )
         );
   }

   // http-errors
   if (isHttpCreatedError(err)) {
      const message =
         err.expose || process.env.NODE_ENV !== 'production'
            ? err.message
            : 'An unexpected server error occurred.';

      return void res
         .status(err.status)
         .json(
            createErrorResponse(
               statusToErrorCode(err.status),
               message,
               requestId
            )
         );
   }

   // Generic status-only. Treating all 4XX as client-safe, all 5XX as opaque.
   if (isStatusOnlyError(err)) {
      const isClientError = err.status >= 400 && err.status < 500;
      const message =
         isClientError || process.env.NODE_ENV !== 'production'
            ? err.message
            : 'An unexpected server error occurred.';

      return void res
         .status(err.status)
         .json(
            createErrorResponse(
               statusToErrorCode(err.status),
               message,
               requestId
            )
         );
   }

   // Generic statusCode-only. Same logic, different property name.
   if (isStatusCodeOnlyError(err)) {
      const isClientError = err.statusCode >= 400 && err.statusCode < 500;
      const message =
         isClientError || process.env.NODE_ENV !== 'production'
            ? err.message
            : 'An unexpected server error occurred.';

      return void res
         .status(err.statusCode)
         .json(
            createErrorResponse(
               statusToErrorCode(err.statusCode),
               message,
               requestId
            )
         );
   }

   // Not an HTTP-like error at all, not our job.
   return next(err);
}

// ===== ENOENT specialist/handler =================================================
export function handleEnoentError(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   // Type guard that narrows `unknown` to Node's built-in ErrnoException type.
   /* We check three things in sequence: 1. It must be an Error — ErrnoException extends Error. 2. It must have a `code` property that is a string — all ErrnoExceptions do. 3. That code must specifically be 'ENOENT' — our target condition. We deliberately do NOT check `err.path` (the filesystem path) here — that property is sensitive and belongs only in the server logs, never in the type guard or the response. */
   function isEnoentError(err: unknown): err is NodeJS.ErrnoException {
      return (
         err instanceof Error &&
         'code' in err &&
         typeof (err as NodeJS.ErrnoException).code === 'string' &&
         (err as NodeJS.ErrnoException).code === 'ENOENT'
      );
   }

   // Passing it to the next specialist if it's not our responsibility
   if (!isEnoentError(err)) return next(err);

   const requestId = res.locals.requestId;

   /* We log the real filesystem path here — on the server, in the logs, where it belongs. This is invaluable for diagnosing deployment issues. `err.path` tells us exactly which file was missing and where Node expected to find it. We intentionally do not include this in the response below. */
   logger.error(
      `sendFile failed — file not found at path: ${err.path ?? 'unknown'}. ` +
         `This likely indicates a missing build artefact or a misconfigured deployment.`
   );

   /* 503 because this is an infrastructure failure, not a code bug. The message is deliberately generic — the client has no business knowing that index.html is missing or where we expected to find it. */
   return void res
      .status(503)
      .json(
         createErrorResponse(
            'SERVICE_UNAVAILABLE',
            'The application is temporarily unavailable. Please try again shortly.',
            requestId
         )
      );
}

// ===== Catch-All specialist/handler ==============================================
export function handleCatchAll(
   err: unknown,
   _req: Request,
   res: Response,
   next: NextFunction
): void {
   const requestId = res.locals.requestId;

   // ── The `res.headersSent` guard ─────────────────────────────────────────
   /* If headers have already been flushed to the client — because a route handler started streaming a response before something threw — we cannot send a new response. Calling next(err) here hands control to Express's own built-in final handler, which will close the connection cleanly. Without this guard, attempting res.json() would itself throw an error, compounding the original problem. */
   if (res.headersSent) {
      logger.error(
         `Error occurred after headers were sent — closing connection. ` +
            `requestId=${requestId ?? 'unknown'}`
      );
      return next(err);
   }

   // ── Normalise the error ─────────────────────────────────────────────────
   /* By this point, every specialist has declined to handle this error. We can't assume it's an Error instance — someone might have thrown a plain string, a number, or any other value. We normalise to Error so the rest of this handler can work with a consistent shape. */
   const error =
      err instanceof Error
         ? err
         : new Error(
              `Non-Error thrown: ${typeof err === 'object' ? JSON.stringify(err) : String(err)}`
           );

   const operational = isOperationalError(error);

   // ── Logging ─────────────────────────────────────────────────────────────
   /* This is the ONE place in the entire pipeline responsible for logging errors that result in a 500 or 503. Every specialist above intentionally deferred this responsibility here.
   We log differently depending on error category:
   • Operational errors get `warn` — they're expected, environmental failures.
   • Programmer errors get `error` — they're bugs that need investigation. */
   if (operational) {
      logger.warn(
         `Operational error reached catch-all (a specialist may be missing). ` +
            `requestId=${requestId ?? 'unknown'} | ` +
            `name=${error.name} | ` +
            `message=${error.message}`
      );
   } else {
      // For programmer errors, we log the full stack trace. The stack is the most valuable diagnostic tool available — it tells you exactly where in the code the error originated.
      logger.error(
         `Unhandled programmer error. ` +
            `requestId=${requestId ?? 'unknown'} | ` +
            `name=${error.name} | ` +
            `message=${error.message}\n${error.stack ?? 'no stack available'}`
      );
   }

   // ── Response ────────────────────────────────────────────────────────────
   /* Operational errors signal a transient infrastructure failure → 503. Programmer errors signal a code bug → 500. In both cases, the message sent to the client is deliberately vague in production. The requestId is the client's handle for reporting the issue back to you — you can then grep your logs for it to find the full details. In development, we expose the real message to speed up debugging. */
   const status = operational ? 503 : 500;
   const code = operational ? 'SERVICE_UNAVAILABLE' : 'INTERNAL_ERROR';
   const message =
      process.env.NODE_ENV === 'production'
         ? operational
            ? 'The service is temporarily unavailable. Please try again shortly.'
            : 'An unexpected error occurred. Please contact support if this persists.'
         : error.message; // In development: the real message, unfiltered.

   return void res
      .status(status)
      .json(createErrorResponse(code, message, requestId));

   // Notice: no next(err) here, ever (except in the headersSent guard above). This handler is the terminal station. There is nobody left to pass to.
}
