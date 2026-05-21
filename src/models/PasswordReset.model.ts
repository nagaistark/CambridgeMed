import mongoose from 'mongoose';
import { StrictSchemaDefinition } from '@utils/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/node_crypto_constants.ts';

// ── Domain types ─────────────────────────────────────────────────────────────────
export type IPasswordResetDefinition = {
   tokenHash: string;
   userId: mongoose.Types.ObjectId;
   expiresAt: Date;
};

export type IPasswordResetDocument = IPasswordResetDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

// ── Mongoose schema definition ───────────────────────────────────────────────────
const PasswordResetDefinition = {
   tokenHash: {
      type: String,
      required: [true, `Token hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, `User ID is required.`],
   },
   expiresAt: {
      type: Date,
      required: [true, `Expiry date is required.`],
   },
} satisfies StrictSchemaDefinition<IPasswordResetDefinition>;

const PasswordResetSchema = new mongoose.Schema<IPasswordResetDocument>(
   PasswordResetDefinition,
   { timestamps: true, strict: 'throw' }
);

/* Primary lookup key. Every redemption request hashes the raw token and queries this field. */
PasswordResetSchema.index({ tokenHash: 1 }, { unique: true });

/* Enforces one active reset per user at the database layer. The application layer (forgotPasswordController) deliberately replaces any existing reset with a fresh one, so this index acts as a safety net rather than a primary gate. */
PasswordResetSchema.index({ userId: 1 }, { unique: true });

/* TTL janitor. */
PasswordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const getPasswordResetModel = createModelGetter<IPasswordResetDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'PasswordReset',
   PasswordResetSchema
);
