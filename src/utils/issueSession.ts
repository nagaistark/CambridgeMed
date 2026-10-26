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
import { Either, Schema } from 'effect';
import { evictExcessSessions } from '@utils/evictExcessSessions.ts';

/* Creates a Session document, signs both tokens, sets the auth cookies. Shared by the password-only login path, the TOTP verification path and the recovery-code path. */
export async function issueSession(
   user: Pick<IUserDocument, '_id' | 'role' | 'permissions'>,
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

   const candidate: ISessionDocument = {
      _id: new ObjectId(),
      userId: user._id,
      currentTokenHash: refreshTokenHash,
      previousTokenHash: null,
      rotatedAt: now,
      expiresAt: new Date(refreshTokenExpirationTimestampMS),
      ipAddress: req.ip ?? null,
      /* `||` on purpose: an empty header must become null too. trim() because slicing can leave trailing whitespace, which the schema rejects. */
      userAgent: req.headers['user-agent']?.slice(0, 512).trim() || null,
      createdAt: now,
      updatedAt: now,
   };

   const decoded = Schema.decodeUnknownEither(SessionDocumentCreateValidator)(
      candidate
   );
   if (Either.isLeft(decoded)) {
      /* Built entirely server-side, so this is a programmer error: a plain Error (logged, vague 500), not a ParseError (which the pipeline would answer with a 422). */
      throw new Error(`Freshly built session failed validation.`, {
         cause: decoded.left,
      });
   }
   const validatedSession = decoded.right;

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
