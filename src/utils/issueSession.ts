import type { Request, Response } from 'express';
import type { IUserDocument } from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   SessionDocumentCreateValidator,
} from '@models/Session_v3.model.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import type { ISessionDocument } from '@models/Session_v3.model.ts';
import { ObjectId } from 'mongodb';
import { evictExcessSessions } from '@utils/evictExcessSessions.ts';
import { ipOrNull } from '@utils/effectSchemaReusables.ts';
import { decodeStored } from '@utils/decodeStored.ts';

/* Creates a Session document, signs both tokens, sets the auth cookies. Shared by the password-only login path, the TOTP verification path and the recovery-code path. */
export async function issueSession(
   user: Pick<IUserDocument, '_id' | 'role' | 'permissions'>,
   req: Request,
   res: Response
): Promise<void> {
   const now = new Date();

   const {
      accessTokenMaxAgeMS,
      refreshTokenMaxAgeMS,
      accessTokenExpirationTimestampMS,
      nextWeeklyResetTimestampMS,
   } = getMaxAgeTokens(now);

   const { raw: rawRefreshToken, hash: refreshTokenHash } =
      generateRefreshToken();

   const candidate: ISessionDocument = {
      _id: new ObjectId(),
      userId: user._id,
      currentTokenHash: refreshTokenHash,
      previousTokenHash: null,
      rotatedAt: now,
      expiresAt: new Date(nextWeeklyResetTimestampMS),
      ipAddress: ipOrNull(req.ip),
      /* `||` on purpose: an empty header must become null too. trim() because slicing can leave trailing whitespace, which the schema rejects. */
      userAgent: req.headers['user-agent']?.slice(0, 512).trim() || null,
      createdAt: now,
      updatedAt: now,
   };

   const validatedSession = decodeStored(
      SessionDocumentCreateValidator,
      candidate,
      'new session document'
   );

   /* Everything fallible happens BEFORE the write that commits. If signing fails, no orphaned session is left behind. */
   const accessToken = await signAccessToken({
      sub: user._id.toString(),
      role: user.role,
      permissions: user.permissions,
      sessionId: validatedSession._id.toString(),
      expirationTime: accessTokenExpirationTimestampMS,
   });

   await getSessionCollection().insertOne(validatedSession);

   await evictExcessSessions(validatedSession.userId, validatedSession._id);

   setAuthCookies(
      res,
      accessToken,
      accessTokenMaxAgeMS,
      rawRefreshToken,
      refreshTokenMaxAgeMS
   );
}
