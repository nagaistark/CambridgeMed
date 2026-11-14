import type { Request, Response, NextFunction } from 'express';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { clearAuthCookies, readSessionTokenCookie } from '@utils/tokenUtils.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

export async function logoutController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      /* Idempotent by design: absent, malformed, expired or already-revoked token all end the same way, with the cookie cleared and a 200. */
      const rawToken = readSessionTokenCookie(req);

      if (rawToken !== undefined) {
         await getSessionCollection().deleteOne({
            tokenHash: generateStandardHash(rawToken),
         } satisfies StrictMongoFilter<ISessionDocument>);
      }

      clearAuthCookies(res);

      return void res.status(200).json(buildAuthResponse('Logout successful.'));
   } catch (err) {
      next(err);
   }
}
