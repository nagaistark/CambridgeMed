import type { Request, NextFunction } from 'express';
import { jwtVerify } from 'jose';
import { getPublicKey } from '@utils/jwtUtils.ts';
import {
   ACCESS_TOKEN_COOKIE_NAME,
   ACCESS_TOKEN_AUDIENCE,
} from '@utils/tokenUtils.ts';
import { allRoles } from '@ssot/user_roles_constants.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { CustomSessionPayload } from '@ssot/jwt_payload_constants.ts';

export async function authenticate(
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const rawToken: string | undefined =
         req.cookies[ACCESS_TOKEN_COOKIE_NAME];

      // ── Token presence check ─────────────────────────────────────────
      /* A missing token is a controlled, expected condition, not an error. We handle it directly rather than throwing. That's how we tell the client "you need to authenticate first". */
      if (!rawToken) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Authentication required`,
                  res.locals.requestId
               )
            );
      }

      // ── Cryptographic verification ───────────────────────────────────
      /* jwtVerify performs four checks simultaneously:
      a) RS256 signature (was this token signed by our private key?)
      b) Expiry (has the `exp` claim passed?)
      c) Audience (does `aud` match ACCESS_TOKEN_AUDIENCE? This prevents email verification tokens from being used as access tokens (token type confusion))
      d) Algorithm (is `alg` exactly RS256? This closes the `alg: none` attack vector)
      
      Any failure throws a JOSEError subclass, which next(err) passes to handleJwtError in the error pipeline. We do not handle those errors here — that is the specialist's job. */

      const publicKey = await getPublicKey();
      const { payload } = await jwtVerify<CustomSessionPayload>(
         rawToken,
         publicKey,
         {
            algorithms: ['RS256'],
            audience: ACCESS_TOKEN_AUDIENCE,
         }
      );
      const session: CustomSessionPayload = payload;

      // ── Defensive payload narrowing ──────────────────────────────────
      const { sub, role, permissions, sessionId } = session;

      /* The following should never happen, normally. It'd mean we issued a malformed token ourselves. We respond with the same vague 401 to avoid leaking internal details. */
      if (
         typeof sub !== 'string' ||
         !allRoles.includes(role) ||
         typeof permissions !== 'number' ||
         typeof sessionId !== 'string'
      ) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid or malformed token.`,
                  res.locals.requestId
               )
            );
      }

      // ── Attach verified identity ──────────────────────────────────────
      /* After all four checks pass (the claims are the right shape), we attach the verified identity to res.locals so every downstream controller can read it without touching the database. This is the authenticated user's passport for the remainder of this request's journey. */
      res.locals.authenticatedUser = {
         sub,
         role,
         permissions,
         sessionId,
      };
      next();
   } catch (err) {
      // Any JOSEError from jwtVerify lands here and travels to handleJwtError.
      next(err);
   }
}
