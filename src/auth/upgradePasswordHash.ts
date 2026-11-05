import {
   getUserCollection,
   UserIdPasswordHashValidator,
   type IUserDocument,
   type IUserIdPasswordHash,
} from '@models/User_v3.model.ts';
import { hashPassword, needsRehash } from '@utils/hashAndVerify.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import logger from '../logger.ts';

/* Call ONLY right after `verifyPassword` succeeded: the plaintext is proven correct, and this is the single moment it can be re-hashed.

   Best-effort by design (same contract as evictExcessSessions): this function never rejects. A failed upgrade must not fail a login whose password was correct; the user is simply upgraded next time. */
export async function upgradePasswordHashIfStale(
   user: IUserIdPasswordHash,
   plaintext: string,
   requestId: string
): Promise<void> {
   try {
      if (!needsRehash(user.passwordHash)) return;

      /* Validate the candidate BEFORE writing it. A hash our own schema would reject on the next read would brick the account (every login would 500). Failing here costs nothing; failing after the write costs a user. */
      const candidate = decodeStored(
         UserIdPasswordHashValidator,
         { _id: user._id, passwordHash: await hashPassword(plaintext) },
         'password hash upgrade candidate'
      );

      /* Compare-and-swap: only replace the hash we verified against. If the user changed or reset their password in the meantime, matchedCount is 0 and we MUST NOT overwrite the newer hash with one derived from the old password. `updatedAt` is deliberately untouched: this is a storage migration, not a profile change. */
      const result = await getUserCollection().updateOne(
         {
            _id: user._id,
            passwordHash: user.passwordHash,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { passwordHash: candidate.passwordHash },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (result.matchedCount === 1) {
         logger.info(`Password hash upgraded to current Argon2 parameters.`, {
            requestId,
            userId: user._id.toHexString(),
         });
      } else {
         logger.debug(
            `Password hash upgrade skipped: hash changed concurrently. requestId=${requestId}`
         );
      }
   } catch (err) {
      logger.error(
         `Password hash upgrade failed. requestId=${requestId} | ${sanitizeError(err).message}`
      );
   }
}
