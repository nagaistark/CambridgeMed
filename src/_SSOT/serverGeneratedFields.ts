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

export const validateChronology = <
   A extends Pick<IServerGeneratedFields, 'createdAt' | 'updatedAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if (doc.createdAt.getTime() > doc.updatedAt.getTime()) {
            issues.push({
               path: ['updatedAt'],
               message: `updatedAt cannot be chronologically before createdAt.`,
            });
         }

         return issues;
      })
   );
};
