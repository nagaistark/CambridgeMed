import mongoose from 'mongoose';
import { allRoles, type UserRole } from '@ssot/user_roles_constants.ts';
import { StrictSchemaDefinition } from '@ssot/mongoose_types.ts';

import {
   email,
   InferOutput,
   maxLength,
   minLength,
   nonEmpty,
   pipe,
   regex,
   strictObject,
   string,
   transform,
   trim,
} from 'valibot';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import {
   NAME_CHANGE_CAP,
   EMAIL_CHANGE_CAP,
} from '@ssot/user_change_constants.ts';

// ── History entry types ──────────────────────────────────────────────────────────
/* Each entry represents a name or email that was once the live value on this account. `archivedAt` records the moment the entry was archived (explicitly set by application code because subdocuments embedded in arrays do not participate in the parent document's timestamp lifecycle). */
export type INameHistoryEntry = Pick<IUserInitial, 'firstName' | 'lastName'> & {
   archivedAt: Date;
};

export type IEmailHistoryEntry = Pick<IUserInitial, 'email'> & {
   archivedAt: Date;
};

// ── Valibot registration schema ──────────────────────────────────────────────────
/* This schema validates the body of POST /api/invites/:token/accept. It is unchanged from its original form — the history/counter additions to the User model are server-side concerns invisible to the registering user. */
export type IUserInitial = InferOutput<typeof UserRegistrationSchema>;

const baseString = pipe(
   string(`Must be a string.`),
   trim(),
   minLength(2, `String should be at least 2 characters long.`),
   maxLength(32, `String is too long.`)
);

export const nameString = pipe(
   baseString,
   regex(
      /^[\p{L} .'\-'']+$/u,
      'Must not contain invalid or consecutive non-alphanumeric characters in name.'
   ),
   transform(name => {
      const words = name
         .split(/[\s-]+/)
         .map(w => `${w.slice(0, 1).toUpperCase()}${w.slice(1).toLowerCase()}`);
      const separators = name.match(/[\s-]+/g) ?? [];
      return words.reduce(
         (acc, cur, idx) => acc + cur + (separators[idx] ?? ''),
         ''
      );
   })
);

export const UserRegistrationSchema = strictObject({
   firstName: nameString,
   lastName: nameString,
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => str.toLowerCase())
   ),
   password: pipe(
      string(`Must be a string.`),
      minLength(8, `Password must be at least 8 characters.`),
      maxLength(128, `Password is too long.`),
      regex(/[A-Z]/, `Password must contain at least one uppercase letter.`),
      regex(/[a-z]/, `Password must contain at least one lowercase letter.`),
      regex(/[0-9]/, `Password must contain at least one number.`)
   ),
});

// ── Domain types ─────────────────────────────────────────────────────────────────
export type IUserDefinition = Omit<IUserInitial, 'password'> & {
   passwordHash: string;
   role: UserRole; // full union — superadmin must be storable
   canIssueInvites: boolean;

   /* Each array grows by one entry every time the corresponding value changes. Once nameChangesUsed / emailChangesUsed reaches NAME_CHANGE_CAP / EMAIL_CHANGE_CAP, further changes are blocked at the application layer. The counters (incremented atomically alongside the array push) are the SSOT for the cap check. */
   previousNames: INameHistoryEntry[];
   previousEmails: IEmailHistoryEntry[];
   nameChangesUsed: number;
   emailChangesUsed: number;

   totpSecret: string | null; // AES-256-GCM encrypted, null until enrollment begins
   isTotpEnabled: boolean; // false until first successful verification post-enrollment
   totpRecoveryCodes: string[]; // Argon2 hashes of the one-time recovery codes

   invitedBy?: mongoose.Types.ObjectId;
   isActive: boolean;

   /* isVerified removed. Email ownership is proven structurally. */
};

export type IUserDocument = IUserDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

/* The SAFE, full (except `passwordHash`) projection for self-view (GET /api/auth/me) and superadmin views. */
export type SafeUser = Omit<IUserDocument, 'passwordHash'>;

/* The minimal PUBLIC-facing shape returned to non-superadmin authenticated users looking up their colleagues. */
export type PublicUser = Pick<
   IUserDocument,
   '_id' | 'firstName' | 'lastName' | 'email' | 'role' | 'canIssueInvites'
>;

// ── HTTP response envelope types ─────────────────────────────────────────────────
export type AuthUserResponse = {
   success: true;
   message: string;
   user: PublicUser;
};

export type AuthUserResponseLogout = Omit<AuthUserResponse, 'user'>;

// ── Subdocument schemas ──────────────────────────────────────────────────────────
/* { _id: false } suppresses the automatic ObjectId that Mongoose adds to every subdocument in an array by default. History entries have no independent identity and are never queried or updated in isolation. */
const nameHistoryEntryDefinition = {
   firstName: { type: String, required: true },
   lastName: { type: String, required: true },
   archivedAt: { type: Date, required: true, default: Date.now },
} satisfies StrictSchemaDefinition<INameHistoryEntry>;

const NameHistoryEntrySchema = new mongoose.Schema<INameHistoryEntry>(
   nameHistoryEntryDefinition,
   { _id: false }
);

const emailHistoryEntryDefinition = {
   email: { type: String, required: true },
   archivedAt: { type: Date, required: true, default: Date.now },
} satisfies StrictSchemaDefinition<IEmailHistoryEntry>;

const EmailHistoryEntrySchema = new mongoose.Schema<IEmailHistoryEntry>(
   emailHistoryEntryDefinition,
   { _id: false }
);

// ── Mongoose schema definition ───────────────────────────────────────────────────
const UserDefinition = {
   firstName: {
      type: String,
      required: [true, `First name is required.`],
      trim: true,
   },
   lastName: {
      type: String,
      required: [true, `Last name is required.`],
      trim: true,
   },
   email: {
      type: String,
      required: [true, `Email is required.`],
      lowercase: true,
      trim: true,
   },
   passwordHash: {
      type: String,
      required: [true, `Password hash is required.`],
   },
   role: {
      type: String,
      enum: {
         values: allRoles, // full universe — allows the superadmin document to exist
         message: `Role must be one of: ${allRoles.join(', ')}`,
      },
      required: [true, `Role is required`],
      validate: {
         validator: function (role: string) {
            return (
               (!!this?.invitedBy && role !== 'superadmin') ||
               (!this?.invitedBy && role === 'superadmin')
            );
         },
         message: `Role invariant violated: the superadmin role may only exist without an invitedBy reference, and all invited users must have an allowed role.`,
      },
   },
   canIssueInvites: {
      type: Boolean,
      required: [true, `Please specify whether the User can issue invites.`],
      default: false,
   },
   previousNames: {
      type: [NameHistoryEntrySchema],
      default: [],
   },
   previousEmails: {
      type: [EmailHistoryEntrySchema],
      default: [],
   },
   nameChangesUsed: {
      type: Number,
      required: [true, `Name change count is required.`],
      default: 0,
      min: [0, `Name change count cannot be negative.`],
      max: [
         NAME_CHANGE_CAP,
         `Name change count cannot exceed the cap of ${NAME_CHANGE_CAP}.`,
      ],
   },
   emailChangesUsed: {
      type: Number,
      required: [true, `Email change count is required.`],
      default: 0,
      min: [0, `Email change count cannot be negative.`],
      max: [
         EMAIL_CHANGE_CAP,
         `Email change count cannot exceed the cap of ${EMAIL_CHANGE_CAP}.`,
      ],
   },
   totpSecret: {
      type: String,
      default: null,
   },
   isTotpEnabled: {
      type: Boolean,
      required: [true, `Specify whether TOTP is enabled.`],
      default: false,
   },
   totpRecoveryCodes: {
      type: [String],
      required: [true, `TOTP Recovery Codes are required.`],
      default: [],
   },
   invitedBy: {
      // Optional because the "required" constraint breaks for the superadmin (who isn't invited by anyone)
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
   },
   isActive: {
      type: Boolean,
      default: true,
      required: [true, `Is the user active?`],
   },
} satisfies StrictSchemaDefinition<IUserDefinition>;

const UserSchema = new mongoose.Schema<IUserDocument>(UserDefinition, {
   timestamps: true,
   strict: 'throw',
});

UserSchema.index({ email: 1 }, { unique: true });

// MODEL FACTORY (lazy getter pattern)
export const getUserModel = createModelGetter<IUserDocument>(
   () => DatabaseManager.getInstance().auth.connection,
   'User',
   UserSchema
);
