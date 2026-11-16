import { allRoles } from '@ssot/user_roles_constants.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import { positiveInteger } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';
import type { ObjectId } from 'mongodb';

/* The authorization atoms: a role and the permission bitmask. Composed into UserDocumentStruct, so what is stored and what a request carries cannot drift apart. */
export const RolePermissionsStruct = Schema.Struct({
   role: Schema.Literal(...allRoles),
   permissions: positiveInteger,
});

/* The principal of the current request. Built by `authenticate` from the database, never from anything the client holds, and already parsed: ids are ObjectId instances, so no controller re-parses a string. */
export type AuthenticatedUser = ExpandType<
   Schema.Schema.Type<typeof RolePermissionsStruct> & {
      readonly userId: ObjectId;
      readonly sessionId: ObjectId;
   }
>;
