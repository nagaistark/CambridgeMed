import mongoose from 'mongoose';
import { allowedRoles } from '@ssot/user_roles_constants.ts';
import { StrictSchemaDefinition } from '@ssot/mongoose_types.ts';
import {
   boolean,
   email,
   InferOutput,
   maxLength,
   nonEmpty,
   pipe,
   strictObject,
   string,
   transform,
} from 'valibot';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { hexHashValidator } from '@ssot/node_crypto_constants.ts';

// This is what the inviter puts in
type IInviteInitial = InferOutput<typeof InviteCreateSchema>;

// This is what we save to the database
export type IInviteDefinition = IInviteInitial & {
   tokenHash: string;
   usedAt: Date | null;
   expiresAt: Date;
   issuedBy: mongoose.Types.ObjectId;
};

// This is what we check the hydrated document against
export type IInviteDocument = IInviteDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

export const InviteCreateSchema = strictObject({
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => {
         return str.toLowerCase();
      })
   ),
   role: makePicklist(allowedRoles), // Allowed Roles only, never a superadmin
   canIssueInvites: boolean(),
});

export type IInviteCreateBody = InferOutput<typeof InviteCreateSchema>;

const InviteDefinition = {
   tokenHash: {
      type: String,
      required: [true, `Token Hash is required.`],
      trim: true,
      validate: hexHashValidator,
   },
   email: {
      type: String,
      required: [true, `Email is required.`],
      lowercase: true,
      trim: true,
   },
   role: {
      type: String,
      enum: {
         values: allowedRoles,
         message: `Role must be one of: ${allowedRoles.join(', ')}`,
      },
      required: [true, `Role is required`],
   },
   canIssueInvites: {
      type: Boolean,
      required: [true, `Please specify whether the User can issue invites.`],
      default: false,
   },
   usedAt: {
      type: Date,
      default: null,
   },
   expiresAt: {
      type: Date,
      required: [true, `When does the invite expire?`],
   },
   issuedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, `Who issued the invite?`],
   },
} satisfies StrictSchemaDefinition<IInviteDefinition>;

const InviteSchema = new mongoose.Schema<IInviteDocument>(InviteDefinition, {
   timestamps: true,
   strict: 'throw',
});

/* NO UNIQUENESS CONSTRAINT! The application layer handles duplicate prevention with a temporally-aware check (usedAt: null, expiresAt: { $gt: new Date() }). A unique index here would cause false 11000 errors during the TTL janitor's 60-second cleanup window after expiry. */
InviteSchema.index({ email: 1 });

InviteSchema.index({ tokenHash: 1 }, { unique: true });
InviteSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// MODEL FACTORY (lazy getter pattern)
export const getInviteModel = createModelGetter<IInviteDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'Invite',
   InviteSchema
);
