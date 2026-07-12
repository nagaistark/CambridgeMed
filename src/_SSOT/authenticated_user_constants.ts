import { allRoles } from '@ssot/user_roles_constants.ts';
import {
   baseString,
   positiveIntegerStringToNumber,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const AUTHENTICATED_USER = Schema.Struct({
   sub: baseString,
   role: Schema.Literal(...allRoles),
   permissions: positiveIntegerStringToNumber,
   sessionId: baseString,
});
