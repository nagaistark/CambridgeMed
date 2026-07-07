import { allRoles } from '@ssot/user_roles_constants.ts';
import {
   baseString,
   positiveIntegerStringToNumber,
} from '@utils/effectSchemaReusables.ts';
import { positiveIntegerDocument } from '@utils/valibotSchemaReusables.ts';
import { Schema } from 'effect';
import { InferOutput, picklist, strictObject, string } from 'valibot';

export const AUTHENTICATED_USER = strictObject({
   sub: string(),
   role: picklist(allRoles),
   permissions: positiveIntegerDocument,
   sessionId: string(),
});

export const AUTHENTICATED_USER_V2 = Schema.Struct({
   sub: baseString,
   role: Schema.Literal(...allRoles),
   permissions: positiveIntegerStringToNumber,
   sessionId: baseString,
});

export type AuthenticatedUser = InferOutput<typeof AUTHENTICATED_USER>;
