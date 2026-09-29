import { MongoServerError } from 'mongodb';

const DUPLICATE_KEY_CODE = 11000 as const;

/* True only for a duplicate-key violation whose violated index includes `field`. */
export function isDuplicateKeyOnField(err: unknown, field: string): boolean {
   if (!(err instanceof MongoServerError) || err.code !== DUPLICATE_KEY_CODE) {
      return false;
   }

   /* MongoServerError has an index signature, so this property is `any`. Assigning to `unknown` forces us to narrow it before use. */
   const keyPattern: unknown = err.keyPattern;

   return (
      typeof keyPattern === 'object' &&
      keyPattern !== null &&
      field in keyPattern
   );
}
