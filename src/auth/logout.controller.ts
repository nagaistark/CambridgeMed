import type { Request, Response, NextFunction } from 'express';
import { getRefreshTokenModel } from '@models/refreshToken.model.ts';
import { clearAuthCookies, hashToken } from '@utils/tokenUtils.ts';
import { REFRESH_TOKEN_COOKIE_NAME } from '@utils/tokenUtils.ts';

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
         const tokenHash = hashToken(rawRefreshToken);
         const RefreshToken = getRefreshTokenModel();

         // Only mark as revoked if the token exists and isn't already revoked.
         // findOneAndUpdate with no result (null) is fine — we just move on.
         await RefreshToken.findOneAndUpdate(
            { tokenHash, isRevoked: false },
            { isRevoked: true, revokedAt: new Date() }
         );
      }

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Logged out successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
