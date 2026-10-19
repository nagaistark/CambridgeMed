import type { ClientSession, ObjectId } from 'mongodb';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

/* After a change to the account's authentication factors, every OTHER device must re-authenticate. The session making the request survives. Pass `session` to run inside a transaction. */
export async function revokeOtherSessions(
   userId: ObjectId,
   currentSessionId: ObjectId,
   options: { readonly session?: ClientSession } = {}
): Promise<number> {
   const result = await getSessionCollection().deleteMany(
      {
         userId,
         _id: { $ne: currentSessionId },
      } satisfies StrictMongoFilter<ISessionDocument>,
      { session: options.session }
   );
   return result.deletedCount;
}
