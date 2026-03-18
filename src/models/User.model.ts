import mongoose from 'mongoose';
import { IUserInitial } from '@validators/user.validator.ts';
import { userRoles, type UserRole } from '@/_SSOT/user_roles_constants.ts';

// This is what we check Mongoose Schema definition against
type IUserDefinition = Omit<IUserInitial, 'password'> & {
   passwordHash: string;
   role: UserRole;
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

const UserDefinition = {
   username: {
      type: String,
      required: [true, `Username is required`],
      lowercase: true,
      trim: true,
   },
   email: {
      type: String,
      required: [true, `Email is required`],
      unique: true,
      lowercase: true,
      trim: true,
   },
   passwordHash: {
      type: String,
      required: [true, `Password hash is required`],
   },
   role: {
      type: String,
      enum: {
         values: userRoles,
         message: `Role must be one of: ${userRoles.join(', ')}`,
      },
      required: [true, `Role is required`],
   },
   isVerified: {
      type: Boolean,
      default: false,
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
