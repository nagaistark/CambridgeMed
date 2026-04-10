import type { Request, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import { DatabaseManager } from 'dbConnect.ts';
import { getUserModel, type IUserInitial } from '@models/User.model.ts';
import { getInviteModel } from '@models/Invite.model.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { TypedResponse } from '@utils/typedResponse.ts';
import { INVITE_TOKEN_REGEX } from '@ssot/invite_constants.ts';

type AcceptInviteParams = { token: string };

export async function acceptInviteController(
   req: Request<AcceptInviteParams>,
   res: TypedResponse<IUserInitial>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;
      const { email, firstName, lastName, password } = res.locals.validatedBody;

      // ── Step 1: Token format check ─────────────────────────────────────────────
      /* Identical strategy to previewInviteController: 404 rather than 400, so that a malformed token is indistinguishable from a non-existent one. This prevents an attacker from using response codes to probe the expected token format. */
      if (!INVITE_TOKEN_REGEX.test(token)) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This invite link is invalid or has expired.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Step 2: Hash the password BEFORE opening the transaction ───────────────
      /* Argon2 is intentionally slow (that's the security guarantee). Keeping a MongoDB transaction open while Argon2 churns would hold server-side resources for 100–300ms unnecessarily. We hash optimistically upfront. If anything downstream fails, we simply discard the hash. */
      const passwordHash = await hashPassword(password);

      // ── Step 3: Derive the token hash ──────────────────────────────────────────
      /* The raw token lives only in the URL and in transit. Never store or compare raw values — only their SHA-256 fingerprints. */
      const tokenHash = createHash('sha256').update(token).digest('hex');

      // ── Step 4: Acquire the auth connection and open a session ─────────────────
      /* Both the Invite and User collections live on the auth connection, so the session must be started there. A null connection here means the database hasn't finished initialising — treating it as an unexpected server error is correct. */
      const authConnection = DatabaseManager.getInstance().auth.connection;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during invite acceptance.`
         );
      }

      const session = await authConnection.startSession();

      /* The try/catch/finally pattern here serves three distinct purposes:
         - The inner try block runs the happy path and handles expected failures (invalid invite, email mismatch) by aborting cleanly.
         - The catch block handles unexpected errors by aborting and rethrowing, so the outer catch can forward them to the error pipeline via next(err).
         - The finally block unconditionally ends the session, which is mandatory — a leaked session is a server-side resource leak that compounds under load. */
      try {
         session.startTransaction();

         const Invite = getInviteModel();
         const User = getUserModel();

         // ── Step 5: Atomic claim ─────────────────────────────────────────────────
         /* This is the race-condition-proof heart of the operation. The filter has three conditions that must ALL be true simultaneously:
            - tokenHash matches (correct invite)
            - usedAt is null (not yet accepted)
            - expiresAt is in the future (not expired, regardless of TTL janitor lag)

         Because findOneAndUpdate maps directly to MongoDB's native findAndModify command, the filter evaluation and the $set write happen as a single indivisible operation at the storage layer. Only one concurrent request can ever win the race to satisfy the filter — the second will find usedAt already set and receive null, triggering the 404 branch below.

         { new: true } returns the document AFTER the update, so we immediately have access to the invite's email, role, canIssueInvites, and issuedBy without a separate read. This is a two-for-one: validation and claiming in a single round trip. */
         const claimedInvite = await Invite.findOneAndUpdate(
            { tokenHash, usedAt: null, expiresAt: { $gt: new Date() } },
            { $set: { usedAt: new Date() } },
            { new: true, session }
         ).lean();

         if (!claimedInvite) {
            await session.abortTransaction();
            /* The abort rolls back the findOneAndUpdate, leaving the invite document completely untouched for any legitimate future use. */
            return void res
               .status(404)
               .json(
                  createErrorResponse(
                     'NOT_FOUND',
                     `This invite link is invalid or has expired.`,
                     undefined,
                     requestId
                  )
               );
         }

         // ── Step 6: Email confirmation check ────────────────────────────────────
         /* The invitee is asked to type their email address during registration. We compare it against invite.email — the authoritative value set at invite creation time — to confirm the person registering is the intended recipient of this specific invite.

         The comparison uses claimedInvite.email directly (already lowercased at storage time by the Mongoose schema) against the body email (already lowercased by the Valibot transform pipeline in UserRegistrationSchema). No manual lowercasing is needed here, but the symmetry is intentional and worth understanding.

         If the check fails, we abort. The abort rolls back the findOneAndUpdate from Step 5, returning usedAt to null — the invite is unclaimed and can be presented again. A failed confirmation attempt must not consume the invite. */
         if (claimedInvite.email !== email) {
            await session.abortTransaction();
            return void res
               .status(400)
               .json(
                  createErrorResponse(
                     'VALIDATION_ERROR',
                     `The email address you entered does not match the one this invite was sent to.`,
                     undefined,
                     requestId
                  )
               );
         }

         // ── Step 7: Create the User document ────────────────────────────────────
         /* Critical: the email we persist comes from claimedInvite.email, not from res.locals.validatedBody.email. The body email served its purpose in the confirmation check above and is now discarded. This is defence-in-depth — the authoritative email is always the one locked into the invite at creation time, never whatever the client chose to submit.

         Role, canIssueInvites, and invitedBy are copied directly from the invite document. These were set by the person who issued the invite and are not negotiable by the registering user.

         isVerified is true by default in the schema, but we set it explicitly here to make the intent unmistakable: possession of this token proves the user controls the invited email address.

         Mongoose's create() with a session requires the array signature. It returns an array of the created documents — we discard the return value because this controller's response carries no user data. */
         await User.create(
            [
               {
                  firstName,
                  lastName,
                  email: claimedInvite.email,
                  passwordHash,
                  role: claimedInvite.role,
                  canIssueInvites: claimedInvite.canIssueInvites,
                  invitedBy: claimedInvite.issuedBy,
                  isVerified: true,
                  isActive: true,
               },
            ],
            { session }
         );

         // ── Step 8: Commit ───────────────────────────────────────────────────────
         /* Both writes — the invite's usedAt timestamp and the new User document — are committed atomically. If this line throws (e.g. a transient network error), the catch block below aborts the transaction and rethrows, so the outer catch can forward to next(err). Neither write lands in the database unless both succeed. */
         await session.commitTransaction();

         // ── Step 9: Respond ──────────────────────────────────────────────────────
         /* 201 Created. Minimal payload — no user data, no tokens. The client is expected to redirect to the login page. The full user lifecycle is now complete: invited → registered → ready to authenticate. */
         return void res.status(201).json({
            success: true,
            message: `Registration successful. You may now log in.`,
         });
      } catch (err) {
         /* An unexpected error occurred somewhere inside the transaction block. We abort to ensure no partial writes persist, then rethrow so the outer catch can hand it to next(err) and the error pipeline. */
         await session.abortTransaction();
         throw err;
      } finally {
         /* This runs whether we committed, aborted, or threw. Ending the session returns its server-side resources to the connection pool. Skipping this would silently leak resources on every failed registration attempt. */
         await session.endSession();
      }
   } catch (err) {
      next(err);
   }
}
