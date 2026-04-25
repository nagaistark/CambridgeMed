import rateLimit, { type RateLimitRequestHandler } from 'express-rate-limit';
import type { Request, Response } from 'express';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   PASSWORD_CHANGE_WINDOW_MS,
   PASSWORD_CHANGE_MAX_REQUESTS,
   NAME_CHANGE_WINDOW_MS,
   NAME_CHANGE_MAX_REQUESTS,
   EMAIL_CHANGE_INITIATE_WINDOW_MS,
   EMAIL_CHANGE_INITIATE_MAX_REQUESTS,
   EMAIL_TOKEN_WINDOW_MS,
   EMAIL_TOKEN_MAX_REQUESTS,
   FORGOT_PASSWORD_WINDOW_MS,
   FORGOT_PASSWORD_MAX_REQUESTS,
   RESET_PASSWORD_WINDOW_MS,
   RESET_PASSWORD_MAX_REQUESTS,
} from '@ssot/rate_limit_constants.ts';

/* Factory that produces a configured rate limiter. All limiters share the same response shape (canonical ApiErrorResponse) so the client sees consistent error structure regardless of which limiter fired. `standardHeaders: 'draft-7'` emits the RateLimit-* headers defined in the IETF draft — useful for the frontend to know how long to wait before retrying. `legacyHeaders: false` suppresses the older X-RateLimit-* headers to avoid sending redundant information. */
function makeRateLimiter(
   windowMs: number,
   max: number
): RateLimitRequestHandler {
   return rateLimit({
      windowMs,
      max,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      handler: (_req: Request, res: Response) => {
         return void res
            .status(429)
            .json(
               createErrorResponse(
                  'RATE_LIMITED',
                  `Too many requests. Please try again later.`,
                  res.locals.requestId
               )
            );
      },
   });
}

// ── Per-route limiter instances ──────────────────────────────────────────────────
/* Each is instantiated once at module load and reused across all requests to its corresponding route. express-rate-limit stores state in memory by default (suitable for a single-process deployment on Render). If we later move to a multi-process setup, DON'T FORGET TO SWAP IN A REDIS STORE. */

export const passwordChangeRateLimiter = makeRateLimiter(
   PASSWORD_CHANGE_WINDOW_MS,
   PASSWORD_CHANGE_MAX_REQUESTS
);

export const nameChangeRateLimiter = makeRateLimiter(
   NAME_CHANGE_WINDOW_MS,
   NAME_CHANGE_MAX_REQUESTS
);

export const emailChangeInitiateRateLimiter = makeRateLimiter(
   EMAIL_CHANGE_INITIATE_WINDOW_MS,
   EMAIL_CHANGE_INITIATE_MAX_REQUESTS
);

/* Shared by both the confirm and cancel token routes (they face the same brute-force enumeration threat and warrant the same ceiling). */
export const emailTokenRateLimiter = makeRateLimiter(
   EMAIL_TOKEN_WINDOW_MS,
   EMAIL_TOKEN_MAX_REQUESTS
);

export const forgotPasswordRateLimiter = makeRateLimiter(
   FORGOT_PASSWORD_WINDOW_MS,
   FORGOT_PASSWORD_MAX_REQUESTS
);

export const resetPasswordRateLimiter = makeRateLimiter(
   RESET_PASSWORD_WINDOW_MS,
   RESET_PASSWORD_MAX_REQUESTS
);
