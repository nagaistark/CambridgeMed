import type { Request, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import { getUserModel } from '@models/User.model.ts';
import { getPasswordResetModel } from '@models/PasswordReset.model.ts';
import { generateRandomToken } from '@ssot/node_crypto_constants.ts';
import { PASSWORD_RESET_TOKEN_EXPIRY_MS } from '@ssot/password_reset_constants.ts';
import { sendPasswordResetEmail } from '@auth/passwordReset.email.ts';
import { TypedResponse } from '@utils/typedResponse.ts';
import type { ForgotPasswordBody } from '@auth/forgotPassword.schema.ts';
import { myEnv } from 'validateConfig.ts';

export async function forgotPasswordController(
   _req: Request,
   res: TypedResponse<ForgotPasswordBody>,
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

      const user = await getUserModel().findOne({ email }).lean();

      /* No account or inactive account: silently do nothing and return the generic response. We do NOT distinguish between these two cases in the response. */
      if (!user || !user.isActive) {
         return genericResponse();
      }

      // ── Token generation ───────────────────────────────────────────────────────
      /* We always replace any existing reset document for this user with a fresh one. This means a user who clicks "Forgot password?" twice always receives the newest link, and the old link becomes permanently inert (the document it pointed to no longer exists). The deleteOne + create pair is intentionally not wrapped in a transaction because the failure modes are acceptable:
         - If deleteOne succeeds and create fails: the user has no pending reset and can try again immediately. No harm done.
         - If both succeed: the happy path. */
      const rawToken = generateRandomToken();
      const tokenHash = createHash('sha256').update(rawToken).digest('hex');
      const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRY_MS);

      const replaceResult = await getPasswordResetModel().replaceOne(
         { userId: user._id },
         { tokenHash, userId: user._id, expiresAt },
         { upsert: true }
      );

      /* matchedCount: 1 + modifiedCount: 1 → replaced an existing reset
         upsertedCount: 1 → freshly created (no prior reset existed)
         anything else → something unexpected happened */
      if (
         replaceResult.modifiedCount === 0 &&
         replaceResult.upsertedCount === 0
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
         await getPasswordResetModel()
            .deleteOne({ userId: user._id })
            .catch(() => undefined);
         throw emailErr;
      }

      return genericResponse();
   } catch (err) {
      next(err);
   }
}
