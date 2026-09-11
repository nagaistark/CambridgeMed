import { stringToObjectId } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const ServerGeneratedFields = Schema.Struct({
   _id: stringToObjectId,
   createdAt: Schema.ValidDateFromSelf,
   updatedAt: Schema.ValidDateFromSelf,
});

export type IServerGeneratedFields = Schema.Schema.Type<
   typeof ServerGeneratedFields
>;
