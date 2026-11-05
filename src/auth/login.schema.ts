import {
   clinicStaffEmail,
   passwordInputString,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const LoginSchema = Schema.Struct({
   email: clinicStaffEmail,
   password: passwordInputString,
});

export type LoginBody = Schema.Schema.Type<typeof LoginSchema>;
