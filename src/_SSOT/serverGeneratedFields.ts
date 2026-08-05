import { stringToObjectId } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

export const serverGeneratedFields = Schema.Struct({
   _id: stringToObjectId,
   createdAt: Schema.ValidDateFromSelf,
   updatedAt: Schema.ValidDateFromSelf,
});

export type ServerGeneratedFields = Schema.Schema.Type<
   typeof serverGeneratedFields
>;
