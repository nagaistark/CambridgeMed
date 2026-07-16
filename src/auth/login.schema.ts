/* It's intentional that login has NO password complexity rules. We are verifying against an existing Argon2 hash, not enforcing creation constraints. maxLength matches the registration ceiling so an over-long payload is rejected early before we even touch the database. */
import { baseString, clinicStaffEmail } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const LoginSchema = Schema.Struct({
   email: clinicStaffEmail,
   password: baseString,
});

export type LoginBody = Schema.Schema.Type<typeof LoginSchema>;
