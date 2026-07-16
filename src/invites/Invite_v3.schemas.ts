import { allowedRoles } from '@ssot/user_roles_constants.ts';
import { clinicStaffEmail } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const InviteCreateSchema = Schema.Struct({
   email: clinicStaffEmail,
   role: Schema.Literal(...allowedRoles),
   canIssueInvites: Schema.Boolean,
});

export type IInviteCreateBody = Schema.Schema.Type<typeof InviteCreateSchema>;
