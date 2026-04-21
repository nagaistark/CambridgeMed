import mongoose from 'mongoose';
import { StrictSchemaDefinition } from '@ssot/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/node_crypto_constants.ts';

type IRefreshTokenDefinition = {
   // SHA-256 hex digest of the raw opaque token sent to the client. We never persist the raw value — only its fingerprint.
   tokenHash: string;
   userId: mongoose.Types.ObjectId;
   expiresAt: Date;
   isRevoked: boolean;

   // Populated the moment this token is invalidated (rotation or logout). Keeps a forensic record: if a revoked token is presented again, we know exactly when it was revoked and can treat the attempt as a reuse attack.
   revokedAt: Date | null;
};

export type IRefreshTokenDocument = IRefreshTokenDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

const RefreshTokenDefinition = {
   tokenHash: {
      type: String,
      required: [true, `Token Hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, `UserId is required.`],
   },
   expiresAt: {
      type: Date,
      required: [true, 'expiresAt is required.'],
   },
   isRevoked: {
      type: Boolean,
      required: [true, 'isRevoked is required.'],
      default: false,
   },
   revokedAt: {
      type: Date,
      default: null,
   },
} satisfies StrictSchemaDefinition<IRefreshTokenDefinition>;

const RefreshTokenSchema = new mongoose.Schema<IRefreshTokenDocument>(
   RefreshTokenDefinition,
   { timestamps: true, strict: 'throw' }
);

RefreshTokenSchema.index({ tokenHash: 1 }, { unique: true });

// TTL index: MongoDB automatically removes expired documents once expiresAt has passed.
RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Needed for "revoke all sessions for this user" — both during reuse detection and any future "logout everywhere" feature.
RefreshTokenSchema.index({ userId: 1 });

export const getRefreshTokenModel = createModelGetter<IRefreshTokenDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'RefreshToken',
   RefreshTokenSchema
);
