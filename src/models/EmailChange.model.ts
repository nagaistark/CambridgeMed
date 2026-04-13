import mongoose from 'mongoose';
import { StrictSchemaDefinition } from '@ssot/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/deterministic_hash_constants.ts';

// ── Domain types ────────────────────────────────────────────────────────────────
type IEmailChangeDefinition = {
   /* Both token hashes are SHA-256 digests of the raw opaque tokens sent in email links. They are independently unique-indexed so that no two EmailChange documents can share either token, which would open the door to cross-record token confusion. */
   confirmTokenHash: string;
   cancelTokenHash: string;

   userId: mongoose.Types.ObjectId;

   /* oldEmail, stored explicitly, because the cancel controller may need to revert a change that has already been confirmed. At that point, User.email has already been overwritten with newEmail and the original value is no longer recoverable from the User document. */
   oldEmail: string;
   newEmail: string;

   /* TTL index target. Both tokens expire together at this moment regardless of their individual usage state. */
   expiresAt: Date;

   /* These are tracked independently, not as a single `usedAt`, because the two tokens have independent lifecycles:
        - confirmedAt: set when the user clicks the confirmation link.
        - cancelledAt: set when the user clicks the cancellation link.
   Crucially, a cancellation can arrive AFTER a confirmation (reversion scenario). A single `usedAt` flag cannot represent that sequence. */
   confirmedAt: Date | null;
   cancelledAt: Date | null;
};

export type IEmailChangeDocument = IEmailChangeDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

// ── Mongoose schema definition ───────────────────────────────────────────────────
const EmailChangeDefinition = {
   confirmTokenHash: {
      type: String,
      required: [true, `Confirm token hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   cancelTokenHash: {
      type: String,
      required: [true, `Cancel token hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, `User ID is required.`],
   },
   oldEmail: {
      type: String,
      required: [true, `Old email is required.`],
      lowercase: true,
      trim: true,
   },
   newEmail: {
      type: String,
      required: [true, `New email is required.`],
      lowercase: true,
      trim: true,
   },
   expiresAt: {
      type: Date,
      required: [true, `Expiry date is required.`],
   },
   confirmedAt: {
      type: Date,
      default: null,
   },
   cancelledAt: {
      type: Date,
      default: null,
   },
} satisfies StrictSchemaDefinition<IEmailChangeDefinition>;

const EmailChangeSchema = new mongoose.Schema<IEmailChangeDocument>(
   EmailChangeDefinition,
   { timestamps: true, strict: 'throw' }
);

// Unique indexes on both hashes. Primary lookup keys for their respective controllers.
EmailChangeSchema.index({ confirmTokenHash: 1 }, { unique: true });
EmailChangeSchema.index({ cancelTokenHash: 1 }, { unique: true });

// Needed to enforce the "one pending change per user" rule at the application layer and to efficiently find a user's active change request.
EmailChangeSchema.index({ userId: 1 });

// TTL janitor.
EmailChangeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const getEmailChangeModel = createModelGetter<IEmailChangeDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'EmailChange',
   EmailChangeSchema
);
