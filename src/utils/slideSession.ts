import { getSessionCollection } from '@models/Session_v3.model.ts';
import type {
   ISessionAuth,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   SESSION_ACTIVITY_THROTTLE_MS,
   SESSION_IDLE_TIMEOUT_MS,
} from '@ssot/session_constants.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import logger from '../logger.ts';

/* Pushes the idle deadline forward, at most once per SESSION_ACTIVITY_THROTTLE_MS. Best-effort by design (same contract as evictExcessSessions): this function never rejects. The request already authenticated, and a failed slide only means an EARLIER idle logoff, which is the safe direction. The failure is logged instead.

   Two independent defences against races:
   1. The filter re-checks, atomically, that the session is STILL alive and STILL due for a write. A session that died a millisecond ago cannot be revived, and concurrent requests produce one write.
   2. `$max` makes every written value monotonic: a slower request carrying an older `now` can never pull a deadline backwards. */
export async function slideSession(
   session: ISessionAuth,
   now: Date
): Promise<void> {
   /* The cheap in-memory decision first: most requests stop here and cost no write. */
   if (
      now.getTime() - session.lastActiveAt.getTime() <
      SESSION_ACTIVITY_THROTTLE_MS
   ) {
      return;
   }

   try {
      /* The idle deadline, capped at the weekly reset. */
      const expiresAt = new Date(
         Math.min(
            now.getTime() + SESSION_IDLE_TIMEOUT_MS,
            session.absoluteExpiresAt.getTime()
         )
      );
      const throttleCutoff = new Date(
         now.getTime() - SESSION_ACTIVITY_THROTTLE_MS
      );

      await getSessionCollection().updateOne(
         {
            _id: session._id,
            lastActiveAt: { $lte: throttleCutoff },
            expiresAt: { $gt: now },
            absoluteExpiresAt: { $gt: now },
         } satisfies StrictMongoFilter<ISessionDocument>,
         {
            $max: { lastActiveAt: now, updatedAt: now, expiresAt },
         } satisfies StrictUpdate<ISessionDocument>
      );
   } catch (err) {
      logger.error(
         `Session activity slide failed: ${sanitizeError(err).message}`,
         { sessionId: session._id.toHexString() }
      );
   }
}
