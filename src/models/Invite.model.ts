import mongoose from 'mongoose';
import { userRoles } from '@ssot/user_roles_constants.ts';
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

// This is what the inviter puts in
type IInviteInitial = InferOutput<typeof InviteCreateSchema>;

// This is what we save to the database
type IInviteDefinition = IInviteInitial & {
   tokenHash: string;
   usedAt: Date | null;
   expiresAt: Date;
   isRevoked: boolean;
   issuedBy: mongoose.Types.ObjectId;
};

// This is what we check the hydrated document against
type IInviteDocument = IInviteDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

const HEX64_REGEX = /^[a-f0-9]{64}$/i;

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
   role: makePicklist(userRoles),
   canIssueInvites: boolean(),
});

const InviteDefinition = {
   tokenHash: {
      type: String,
      required: [true, `Token Hash is required.`],
      trim: true,
      validate: {
         validator: str => HEX64_REGEX.test(str),
         message: `Token Hash does not conform to the pattern.`,
      },
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
         values: userRoles,
         message: `Role must be one of: ${userRoles.join(', ')}`,
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
   isRevoked: {
      type: Boolean,
      required: [true, `Specify whether the invite has been revoked.`],
      default: false,
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

InviteSchema.index({ tokenHash: 1 }, { unique: true });
InviteSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// MODEL FACTORY (lazy getter pattern)
export const getInviteModel = createModelGetter<IInviteDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'Invite',
   InviteSchema
);
