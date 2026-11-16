import type { ClientSession, ObjectId } from 'mongodb';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { revokeOtherSessions } from '@auth/revokeOtherSessions.ts';
import { makeAppError } from '../errorHandlers.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

type KeepSessionParams = ExpandType<
   Pick<ISessionDocument, 'userId' | 'credentialsVersion'> & {
      readonly sessionId: ObjectId;
   }
>;

/* After an in-session change that bumps `credentialsVersion` but must NOT log the actor out: re-stamp THIS session with the new version and delete every other one. Must run in the same transaction as the bump; if the session vanished meanwhile it throws, which rolls the whole change back. */
export async function keepOnlyCurrentSession(
   params: KeepSessionParams,
   options: { readonly session?: ClientSession } = {}
): Promise<void> {
   const { userId, sessionId, credentialsVersion } = params;
   const now = new Date();

   const restamped = await getSessionCollection().updateOne(
      {
         _id: sessionId,
         userId,
         expiresAt: { $gt: now },
      } satisfies StrictMongoFilter<ISessionDocument>,
      {
         $set: { credentialsVersion, updatedAt: now },
      } satisfies StrictUpdate<ISessionDocument>,
      { session: options.session }
   );

   if (restamped.matchedCount === 0) {
      throw makeAppError(
         'SESSION_REVOKED',
         401,
         'UNAUTHORIZED',
         `Your session is no longer valid. Please log in again.`
      );
   }

   await revokeOtherSessions(userId, sessionId, options);
}
