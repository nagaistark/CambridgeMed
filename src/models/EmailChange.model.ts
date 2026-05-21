import mongoose from 'mongoose';
import { StrictSchemaDefinition } from '@utils/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/node_crypto_constants.ts';
import { InitiateEmailChangeBody } from '@users/User.schemas.ts';

// ── Domain types ─────────────────────────────────────────────────────────────────
export type IEmailChangeDefinition = InitiateEmailChangeBody & {
   confirmTokenHash: string;
   cancelTokenHash: string;
   userId: mongoose.Types.ObjectId;
   oldEmail: string;

   /* TTL index target. Both tokens expire together at this moment regardless of their individual usage state. */
   expiresAt: Date;

   confirmedAt: Date | null;
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
} satisfies StrictSchemaDefinition<IEmailChangeDefinition>;

const EmailChangeSchema = new mongoose.Schema<IEmailChangeDocument>(
   EmailChangeDefinition,
   { timestamps: true, strict: 'throw' }
);

// Unique indexes on both hashes. Primary lookup keys for their respective controllers.
EmailChangeSchema.index({ confirmTokenHash: 1 }, { unique: true });
EmailChangeSchema.index({ cancelTokenHash: 1 }, { unique: true });

// Needed to enforce the "one pending change per user" rule at the application and database layers.
EmailChangeSchema.index({ userId: 1 }, { unique: true });

// TTL janitor.
EmailChangeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const getEmailChangeModel = createModelGetter<IEmailChangeDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'EmailChange',
   EmailChangeSchema
);
