import type { Request, Response } from 'express';
import type { IUserDocument } from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   SessionDocumentCreateValidator,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { generateSessionToken, setSessionCookie } from '@utils/tokenUtils.ts';
import { getNextWeeklyReset } from '@utils/getNextWeeklyReset.ts';
import { SESSION_IDLE_TIMEOUT_MS } from '@ssot/session_constants.ts';
import { ObjectId } from 'mongodb';
import { evictExcessSessions } from '@utils/evictExcessSessions.ts';
import { ipOrNull } from '@utils/effectSchemaReusables.ts';
import { decodeStored } from '@utils/decodeStored.ts';

/* Creates a Session document and sets the session cookie. Shared by the password-only login path, the TOTP verification path and the recovery-code path. Needs nothing but the user's id: role and permissions are read fresh from the database on every request, so they are deliberately NOT captured here.

   Always mints a brand-new token and never looks at any cookie the client already sent, so a client cannot choose (fixate) its own session identifier. */
export async function issueSession(
   user: Pick<IUserDocument, '_id'>,
   req: Request,
   res: Response
): Promise<void> {
   const now = new Date();

   /* The weekly reset is the hard ceiling; the idle deadline starts one timeout away, but never past it (a login at 23:59 on Sunday). */
   const absoluteExpiresAt = getNextWeeklyReset(now);
   const expiresAt = new Date(
      Math.min(
         now.getTime() + SESSION_IDLE_TIMEOUT_MS,
         absoluteExpiresAt.getTime()
      )
   );

   const { raw: rawToken, hash: tokenHash } = generateSessionToken();

   const candidate: ISessionDocument = {
      _id: new ObjectId(),
      userId: user._id,
      tokenHash,
      lastActiveAt: now,
      absoluteExpiresAt,
      expiresAt,
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

   /* Everything fallible happens BEFORE the write that commits. */
   await getSessionCollection().insertOne(validatedSession);

   await evictExcessSessions(validatedSession.userId, validatedSession._id);

   setSessionCookie(res, rawToken, absoluteExpiresAt.getTime() - now.getTime());
}
