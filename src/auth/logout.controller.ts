import type { Request, Response, NextFunction } from 'express';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { clearAuthCookies, readRefreshTokenCookie } from '@utils/tokenUtils.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

export async function logoutController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      /* Idempotent by design: absent, malformed, expired or already-revoked token all end the same way, with cookies cleared and a 200. */
      const rawRefreshToken = readRefreshTokenCookie(req);

      if (rawRefreshToken !== undefined) {
         const tokenHash = generateStandardHash(rawRefreshToken);

         /* The browser virtually always holds the CURRENT token. A stale cookie (previousTokenHash, e.g. a replayed response) is cleaned up charitably, because the user explicitly asked to log out. One atomic delete covers both. */
         await getSessionCollection().deleteOne({
            $or: [
               { currentTokenHash: tokenHash },
               { previousTokenHash: tokenHash },
            ],
         } satisfies StrictMongoFilter<ISessionDocument>);
      }

      clearAuthCookies(res);

      return void res.status(200).json(buildAuthResponse('Logout successful.'));
   } catch (err) {
      next(err);
   }
}
