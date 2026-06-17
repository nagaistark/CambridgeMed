import { allRoles } from '@ssot/user_roles_constants.ts';
import { positiveIntegerInputString } from '@utils/valibotSchemaReusables.ts';
import { InferOutput, picklist, strictObject, string } from 'valibot';

export const AUTHENTICATED_USER = strictObject({
   sub: string(),
   role: picklist(allRoles),
   permissions: positiveIntegerInputString,
   sessionId: string(),
});

export type AuthenticatedUser = InferOutput<typeof AUTHENTICATED_USER>;
