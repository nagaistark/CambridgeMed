import { allRoles } from '@ssot/user_roles_constants.ts';
import {
   objectIdInput,
   positiveInteger,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const AUTHENTICATED_USER = Schema.Struct({
   sub: objectIdInput,
   role: Schema.Literal(...allRoles),
   permissions: positiveInteger,
   sessionId: objectIdInput,
});

export type AuthenticatedUser = Schema.Schema.Type<typeof AUTHENTICATED_USER>;
