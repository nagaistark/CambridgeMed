import { UserInputSchema } from '@models/User_v3.model.ts';
import { rawTokenString } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const AcceptInviteSchema = Schema.Struct({
   token: rawTokenString,
   ...UserInputSchema.fields,
});

export type AcceptInviteBody = Schema.Schema.Type<typeof AcceptInviteSchema>;
