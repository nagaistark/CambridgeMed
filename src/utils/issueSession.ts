import type { Request, Response } from 'express';
import type { IUserDocument } from '@models/User.model.ts';
import { getSessionModel } from '@models/Session.model.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';

/* Creates a Session document, signs both tokens, sets the auth cookies. This encapsulates the "complete a login" operation, which is shared by three controllers: the password-only login path, the TOTP verification path, and the recovery code path. Any future change to session structure happens here and propagates everywhere automatically. */
export async function issueSession(
   user: IUserDocument,
   req: Request,
   res: Response
): Promise<void> {
   const {
      ATMA: accessTokenMaxAge,
      RTMA: refreshTokenMaxAge,
      ATEXP: accessTokenExpirationTime,
      RTEXP: refreshTokenExpirationTime,
   } = getMaxAgeTokens();

   const { raw: rawRefreshToken, hash: refreshTokenHash } =
      generateRefreshToken();

   const sessionDoc = await getSessionModel().create({
      userId: user._id,
      currentTokenHash: refreshTokenHash,
      previousTokenHash: null,
      rotatedAt: new Date(),
      expiresAt: new Date(refreshTokenExpirationTime),
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent']?.slice(0, 512) ?? 'unknown',
   });

   const accessToken = await signAccessToken({
      sub: user._id.toString(),
      role: user.role,
      permissions: user.permissions,
      sessionId: sessionDoc._id.toString(),
      expirationTime: accessTokenExpirationTime,
   });

   setAuthCookies(
      res,
      accessToken,
      accessTokenMaxAge,
      rawRefreshToken,
      refreshTokenMaxAge
   );
}
