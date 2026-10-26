import type { ObjectId } from 'mongodb';
import {
   getSessionCollection,
   SessionOwnerArrayValidator,
   type ISessionDocument,
   type ISessionOwner,
} from '@models/Session_v3.model.ts';
import { SESSION_OWNER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { MAX_SESSIONS_PER_USER } from '@ssot/access_refresh_tokens_constants.ts';
import { LIST_QUERY_MAX_TIME_MS } from '@ssot/pagination_constants.ts';
import type {
   StrictFindOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import { sanitizeError } from '../mongoDBConnect.ts';
import logger from '../logger.ts';

/* Enforces MAX_SESSIONS_PER_USER AFTER the new session has been inserted. Of the user's OTHER sessions, the newest (MAX - 1) survive and the rest are deleted, so the new session can never evict itself. Concurrent logins each trim after their own insert, so the count converges to the cap.

   Best-effort by design: this function never rejects. By the time it runs the new session exists, so failing the login here would strand a session nobody holds a cookie for. The failure is logged instead. Served by the { userId: 1, _id: -1 } index. */
export async function evictExcessSessions(
   userId: ObjectId,
   newSessionId: ObjectId
): Promise<void> {
   try {
      const sessionCollection = getSessionCollection();

      const excessRaw = await sessionCollection
         .find<ISessionOwner>(
            {
               userId,
               _id: { $ne: newSessionId },
            } satisfies StrictMongoFilter<ISessionDocument>,
            {
               projection: SESSION_OWNER_PROJECTION,
               sort: { _id: -1 },
               skip: MAX_SESSIONS_PER_USER - 1,
               maxTimeMS: LIST_QUERY_MAX_TIME_MS,
            } satisfies StrictFindOptions<ISessionDocument>
         )
         .toArray();

      if (excessRaw.length === 0) return;

      const decoded = Schema.decodeUnknownEither(SessionOwnerArrayValidator)(
         excessRaw
      );
      if (Either.isLeft(decoded)) {
         throw new Error(`Stored sessions failed validation during eviction.`, {
            cause: decoded.left,
         });
      }

      const result = await sessionCollection.deleteMany({
         userId,
         _id: { $in: decoded.right.map(s => s._id) },
      } satisfies StrictMongoFilter<ISessionDocument>);

      logger.info(
         `Session cap reached: evicted ${result.deletedCount} oldest session(s).`,
         { userId: userId.toHexString() }
      );
   } catch (err) {
      logger.error(
         `Session cap enforcement failed: ${sanitizeError(err).message}`
      );
   }
}
