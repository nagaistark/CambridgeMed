import mongoose from 'mongoose';
import { StrictSchemaDefinition } from '@ssot/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/node_crypto_constants.ts';

type ISessionDefinition = {
   userId: mongoose.Types.ObjectId;

   // SHA-256 hex digest of the raw opaque token currently valid for this session. Primary lookup key on every refresh request.
   currentTokenHash: string;

   // SHA-256 hex digest of the immediately preceding token. Null only for the very first token issued at login (no rotation has occurred yet). Kept for two purposes: 1. Race condition tolerance: a simultaneous refresh from another tab will present this hash within a short grace window → treat as benign. 2. Reuse detection: this hash arriving AFTER the grace window means a rotated token was re-presented → nuclear as malicious.
   previousTokenHash: string | null;

   // The moment the currentTokenHash was last written. Used to calculate the grace window.
   rotatedAt: Date;

   // The TTL index on this field causes MongoDB to automatically purge the session document at the weekly reset, regardless of whether the user explicitly logged out.
   expiresAt: Date;

   // Device-metadata (captured once at login, never mutated)
   ipAddress: string;
   userAgent: string;
};

export type ISessionDocument = ISessionDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

const SessionDefinition = {
   userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, `UserId is required.`],
   },
   currentTokenHash: {
      type: String,
      required: [true, `Current Token Hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   previousTokenHash: {
      type: String,
      default: null,
      trim: true,
      validate: hexHashValidator,
   },
   rotatedAt: {
      type: Date,
      required: [true, `The timestamp of rotation is required.`],
   },
   expiresAt: {
      type: Date,
      required: [true, `The time of expiration is required.`],
   },
   ipAddress: {
      type: String,
      required: [true, `IP address is required.`],
      trim: true,
   },
   userAgent: {
      type: String,
      required: [true, `User-Agent is required.`],
      trim: true,
      maxlength: [512, `User-Agent string is too long.`],
   },
} satisfies StrictSchemaDefinition<ISessionDefinition>;

const SessionSchema = new mongoose.Schema<ISessionDocument>(SessionDefinition, {
   timestamps: true,
   strict: 'throw',
});

SessionSchema.index({ currentTokenHash: 1 }, { unique: true });

SessionSchema.index({ previousTokenHash: 1 }, { sparse: true });

// Needed for "nuclear" option. If reuse is confirmed, call deleteMany({ userId }) to destroy all active sessions for the affected user in one operation.
SessionSchema.index({ userId: 1 });

// TTL index: MongoDB automatically removes expired documents once expiresAt has passed.
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const getSessionModel = createModelGetter<ISessionDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'Session',
   SessionSchema
);
