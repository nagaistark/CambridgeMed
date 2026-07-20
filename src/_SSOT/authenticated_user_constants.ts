import { allRoles } from '@ssot/user_roles_constants.ts';
import { baseString, positiveInteger } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const AUTHENTICATED_USER = Schema.Struct({
   sub: baseString,
   role: Schema.Literal(...allRoles),
   permissions: positiveInteger,
   sessionId: baseString,
});

export type AuthenticatedUser = Schema.Schema.Type<typeof AUTHENTICATED_USER>;
