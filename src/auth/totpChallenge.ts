import { ObjectId, type ClientSession } from 'mongodb';
import type { Response } from 'express';
import {
   getTotpChallengeCollection,
   TotpChallengeCreateValidator,
   type ITotpChallengeDocument,
} from '@models/TotpChallenge_v3.model.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import { TOTP_CHALLENGE_EXPIRY_SECONDS } from '@ssot/totp_constants.ts';
import { setTotpChallengeCookie } from '@utils/tokenUtils.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

/* One message for every way a challenge can be unusable (unknown, expired, already spent): no oracle. */
export const TOTP_CHALLENGE_EXPIRED_MESSAGE =
   `Your login attempt has expired. Please log in again.` as const;

/* Called by loginController AFTER the password has been proven. Puts the user's CURRENT challenge in their slot (replacing any earlier one: the old link in the chain dies) and sets the cookie. Everything fallible happens before the cookie is set.

   Atomic by one upsert on `userId`. When two logins race to create the very first document, the unique index rejects the loser's insert (duplicate key on `userId`); the loser simply repeats the same update, which now MATCHES the winner's document and replaces it. The last writer wins, and exactly one challenge exists. */
export async function issueTotpChallenge(
   userId: ObjectId,
   res: Response
): Promise<void> {
   const rawToken = generateRandomToken();
   const now = new Date();

   const candidate: ITotpChallengeDocument = {
      _id: new ObjectId(),
      userId,
      tokenHash: generateStandardHash(rawToken),
      expiresAt: new Date(
         now.getTime() + TOTP_CHALLENGE_EXPIRY_SECONDS * 1_000
      ),
      createdAt: now,
      updatedAt: now,
   };

   const validated = decodeStored(
      TotpChallengeCreateValidator,
      candidate,
      'TOTP challenge payload'
   );

   const filter = {
      userId: validated.userId,
   } satisfies StrictMongoFilter<ITotpChallengeDocument>;

   /* `createdAt` is re-set on replacement on purpose: it records when THIS challenge was issued, so `expiresAt > createdAt` stays meaningful. `_id` is seeded only on insert (it is immutable), and `userId` comes from the filter's equality clause. */
   const update = {
      $set: {
         tokenHash: validated.tokenHash,
         expiresAt: validated.expiresAt,
         createdAt: validated.createdAt,
         updatedAt: validated.updatedAt,
      },
      $setOnInsert: { _id: validated._id },
   } satisfies StrictUpdate<ITotpChallengeDocument>;

   const collection = getTotpChallengeCollection();
   try {
      await collection.updateOne(filter, update, { upsert: true });
   } catch (err) {
      if (!isDuplicateKeyOnField(err, 'userId')) throw err;
      await collection.updateOne(filter, update, { upsert: true });
   }

   setTotpChallengeCookie(res, rawToken);
}

/* Spends (deletes) one challenge. true = THIS call spent it; false = it was already gone or has expired (somebody else spent it first, or the clock ran out). A challenge is single-use: whoever gets `true` owns the login. */
export async function consumeTotpChallenge(
   challengeId: ObjectId,
   now: Date
): Promise<boolean> {
   const result = await getTotpChallengeCollection().deleteOne({
      _id: challengeId,
      expiresAt: { $gt: now },
   } satisfies StrictMongoFilter<ITotpChallengeDocument>);
   return result.deletedCount === 1;
}

/* Kills every pending challenge of a user. Called wherever the user's sessions are swept (password change/reset, email change, deactivation, admin 2FA reset): a pre-session credential must die with the session credentials, or somebody who proved the OLD password could still finish a login with a second factor. Pass `session` to run inside the caller's transaction. */
export async function revokeTotpChallenges(
   userId: ObjectId,
   options: { readonly session?: ClientSession } = {}
): Promise<void> {
   await getTotpChallengeCollection().deleteMany(
      { userId } satisfies StrictMongoFilter<ITotpChallengeDocument>,
      { session: options.session }
   );
}
