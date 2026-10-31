import type { Request, NextFunction } from 'express';
import { jwtVerify } from 'jose';
import { getPublicKey } from '@utils/jwtUtils.ts';
import { ACCESS_TOKEN_AUDIENCE } from '@utils/tokenUtils.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { readAccessTokenCookie } from '@utils/tokenUtils.ts';
import { Either, Schema } from 'effect';
import { AUTHENTICATED_USER } from '@ssot/authenticated_user_constants.ts';
import { JWT_ISSUER } from '@ssot/jwt_constants.ts';

export async function authenticate(
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const rawToken = readAccessTokenCookie(req);

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

      const { payload } = await jwtVerify(rawToken, publicKey, {
         algorithms: ['RS256'],
         audience: ACCESS_TOKEN_AUDIENCE,
         issuer: JWT_ISSUER,
      });

      const decodedPayload =
         Schema.decodeUnknownEither(AUTHENTICATED_USER)(payload);

      if (Either.isLeft(decodedPayload)) {
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
      res.locals.authenticatedUser = decodedPayload.right;
      next();
   } catch (err) {
      // Any JOSEError from jwtVerify lands here and travels to handleJwtError.
      next(err);
   }
}
