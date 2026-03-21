import mongoose from 'mongoose';
import { userRoles, type UserRole } from '@ssot/user_roles_constants.ts';

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

// This is what we expect from a User
export type IUserInitial = InferOutput<typeof UserRegistrationSchema>;

// This is what we check Mongoose Schema definition against
type IUserDefinition = Omit<IUserInitial, 'password'> & {
   passwordHash: string;
   role: UserRole;
   canIssueInvites: boolean;
   invitedBy?: mongoose.Types.ObjectId;
   isVerified: boolean;
   isActive: boolean;
};

// This is what we check the hydrated document against
type IUserDocument = IUserDefinition & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

type StrictSchemaDefinition<T> = {
   [K in keyof T]-?: mongoose.SchemaDefinitionProperty<T[K]>;
};

const baseString = pipe(
   string(`Must be a string.`),
   trim(),
   minLength(2, `String should be at least 2 character long.`),
   maxLength(32, `String is too long.`)
);

const nameString = pipe(
   baseString,
   regex(
      /^[\p{L} .'\-‘’]+$/u,
      'Must not contain invalid or consecutive non-alphanumeric characters in name (valibot)'
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

// 1. A User accepts an invite and signs up. Valibot validates the incoming HTTP POST request.
export const UserRegistrationSchema = strictObject({
   firstName: nameString,
   lastName: nameString,
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => {
         return str.toLowerCase();
      })
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

const UserDefinition = {
   firstName: {
      type: String,
      required: [true, `Username is required.`],
      trim: true,
   },
   lastName: {
      type: String,
      required: [true, `Username is required.`],
      trim: true,
   },
   email: {
      type: String,
      required: [true, `Email is required.`],
      unique: true,
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
   invitedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
   },
   isVerified: {
      type: Boolean,
      default: true, // The fact that the User activates the invite (that was sent to their email) proves that they have access to the email.
   },
   isActive: {
      type: Boolean,
      default: true,
   },
} satisfies StrictSchemaDefinition<IUserDefinition>;

const UserSchema = new mongoose.Schema<IUserDocument>(UserDefinition, {
   timestamps: true,
   strict: 'throw',
});

// TBH `<IUserDocument>` doesn't really constrain anything that goes in, but it precisely describes what comes out. It's more like a return-type declaration on a function
export const UserModel = mongoose.model<IUserDocument>('User', UserSchema);
