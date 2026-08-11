import type { Request, Response, NextFunction } from 'express';
import {
   getSessionCollection,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import {
   clearAuthCookies,
   REFRESH_TOKEN_COOKIE_NAME,
} from '@utils/tokenUtils.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

export async function logoutController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      /* Logout is intentionally idempotent. If the cookie is absent or the token is already revoked or expired, we still clear cookies and return 200. From the client's perspective, the outcome is the same: no active session. */
      const rawRefreshToken: string | undefined =
         req.cookies[REFRESH_TOKEN_COOKIE_NAME];

      if (rawRefreshToken) {
         const tokenHash = generateStandardHash(rawRefreshToken);
         const sessionCollection = getSessionCollection();

         /* The browser always sends the most recently issued cookie, so the incoming hash will virtually always match currentTokenHash. We attempt that first. If it matches nothing (the session was already cleaned up by a prior logout or the TTL janitor), deleteOne simply reports zero deletions and we move on — no error, no problem. */
         const result = await sessionCollection.deleteOne({
            currentTokenHash: tokenHash,
         } satisfies StrictMongoFilter<ISessionDocument>);

         /* Edge case: the browser somehow held onto a previousTokenHash cookie (e.g., a network glitch replayed an old response). We make a best-effort attempt to clean up that stale session too. This is not a reuse-detection scenario — the user explicitly asked to log out, so the charitable interpretation always applies. */
         if (result.deletedCount === 0) {
            await sessionCollection.deleteOne({
               previousTokenHash: tokenHash,
            } satisfies StrictMongoFilter<ISessionDocument>);
         }
      }

      clearAuthCookies(res);

      return void res.status(200).json(buildAuthResponse('Logout successful.'));
   } catch (err) {
      next(err);
   }
}
