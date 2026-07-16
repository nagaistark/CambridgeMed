import type { Request, Response } from 'express';
import type { IUserDocument } from '@models/User_v3.model.ts';
import { getSessionCollection } from '@models/Session_v3.model.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { ISessionDoc } from '@models/Session_v3.model.ts';
import { ObjectId } from 'mongodb';

/* Creates a Session document, signs both tokens, sets the auth cookies. This encapsulates the "complete a login" operation, which is shared by three controllers: the password-only login path, the TOTP verification path, and the recovery code path. Any future change to session structure happens here and propagates everywhere automatically. */
export async function issueSession(
   user: IUserDocument,
   req: Request,
   res: Response
): Promise<void> {
   const {
      accessTokenMaxAgeMS,
      refreshTokenMaxAgeMS,
      accessTokenExpirationTimestampMS,
      refreshTokenExpirationTimestampMS,
   } = getMaxAgeTokens();

   const { raw: rawRefreshToken, hash: refreshTokenHash } =
      generateRefreshToken();

   const now = new Date();

   const payload: ISessionDoc = {
      _id: new ObjectId(),
      userId: user._id,
      currentTokenHash: refreshTokenHash,
      previousTokenHash: null,
      rotatedAt: new Date(),
      expiresAt: new Date(refreshTokenExpirationTimestampMS),
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent']?.slice(0, 512) ?? 'unknown',
      createdAt: now,
      updatedAt: now,
   };

   const sessionDoc = await getSessionCollection().insertOne(payload);

   const accessToken = await signAccessToken({
      sub: user._id.toString(),
      role: user.role,
      permissions: user.permissions,
      sessionId: sessionDoc.insertedId.toString(),
      expirationTime: accessTokenExpirationTimestampMS,
   });

   setAuthCookies(
      res,
      accessToken,
      accessTokenMaxAgeMS,
      rawRefreshToken,
      refreshTokenMaxAgeMS
   );
}
