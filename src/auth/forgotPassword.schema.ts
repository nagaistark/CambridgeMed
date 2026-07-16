import { clinicStaffEmail } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const ForgotPasswordSchema = Schema.Struct({
   email: clinicStaffEmail,
});

export type ForgotPasswordBody = Schema.Schema.Type<
   typeof ForgotPasswordSchema
>;
