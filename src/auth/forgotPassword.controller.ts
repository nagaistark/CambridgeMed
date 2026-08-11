import type { Request, NextFunction } from 'express';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import {
   getPasswordResetCollection,
   IPasswordResetDocument,
} from '@models/PasswordReset_v3.model.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import { PASSWORD_RESET_TOKEN_EXPIRY_MS } from '@ssot/password_reset_constants.ts';
import { sendPasswordResetEmail } from '@auth/passwordReset.email.ts';
import { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { ForgotPasswordBody } from '@auth/forgotPassword.schema.ts';
import { myEnv } from '../validateConfig.ts';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

export async function forgotPasswordController(
   _req: Request,
   res: ResponseWithValidatedBody<ForgotPasswordBody>,
   next: NextFunction
): Promise<void> {
   try {
      const { email } = res.locals.validatedBody;

      // ── The invariant response ─────────────────────────────────────────────────
      /* This exact message goes to the client in EVERY case where the email address is structurally valid — whether the account exists, doesn't exist, is inactive, or the email simply wasn't in the database. Returning anything different for any of those cases hands an attacker a user-enumeration oracle. We define it once here so there is no way to accidentally return something else below. */
      const genericResponse = (): void => {
         void res.status(200).json({
            success: true,
            message: `If an account with that email address exists, a reset link has been sent.`,
         });
      };

      const user = await getUserCollection().findOne({
         email,
      } satisfies StrictMongoFilter<IUserDocument>);

      /* No account or inactive account: silently do nothing and return the generic response. We do NOT distinguish between these two cases in the response. */
      if (!user || !user.isActive) {
         return genericResponse();
      }

      // ── Token generation ───────────────────────────────────────────────────────
      const rawToken = generateRandomToken();
      const tokenHash = generateStandardHash(rawToken);
      const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRY_MS);

      const now = new Date();

      /*
         Scenario A: The document EXISTS (It is an Update). MongoDB applies only the `$set` block and completely ignores the `$setOnInsert` block. Result: `updatedAt` is updated while `createdAt` remains untouched (preserving the original timestamp).

         Scenario B: The document DOES NOT EXIST (It is an Insert). MongoDB merges both the `$set` and the `$setOnInsert` blocks together to build the new document. Result: `updatedAt` (from $set) and `createdAt` (from $setOnInsert) are both written to the new document.

         The `$setOnInsert` operator is strictly bound to the `upsert` option.
      */
      const updateResult = await getPasswordResetCollection().updateOne(
         {
            userId: user._id,
         } satisfies StrictMongoFilter<IPasswordResetDocument>,
         {
            $set: {
               tokenHash,
               expiresAt,
               updatedAt: now,
            },
            $setOnInsert: {
               userId: user._id,
               createdAt: now,
            },
         } satisfies StrictUpdate<IPasswordResetDocument>,
         { upsert: true }
      );

      /* matchedCount: 1 + modifiedCount: 1 → replaced an existing reset
         upsertedCount: 1 → freshly created (no prior reset existed)
         anything else → something unexpected happened */
      if (
         updateResult.modifiedCount === 0 &&
         updateResult.upsertedCount === 0
      ) {
         throw new Error(
            `Password reset document was neither created nor replaced for userId: ${user._id.toString()}`
         );
      }

      // ── Email delivery with rollback ───────────────────────────────────────────
      /* Mirrors the same pattern as initiateEmailChangeController. A PasswordReset document that was never delivered is actively harmful — it blocks re-initiation for 30 minutes while the user has no actionable link. Rolling back removes that obstacle. The email error is re-thrown and becomes a 500, which is honest: "something went wrong, try again." It does not confirm whether the account exists. */
      const resetUrl = `${myEnv.appBaseUrl}/reset-password/${rawToken}`;

      try {
         await sendPasswordResetEmail({
            firstName: user.firstName,
            email: user.email,
            resetUrl,
            expiresAt,
         });
      } catch (emailErr) {
         await getPasswordResetCollection()
            .deleteOne({ userId: user._id })
            .catch(() => undefined);
         throw emailErr;
      }

      return genericResponse();
   } catch (err) {
      next(err);
   }
}
