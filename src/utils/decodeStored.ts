// src/utils/decodeStored.ts
import { Either, Schema } from 'effect';

/* For data the SERVER produced or read from its own database. A failure here is a bug or data drift (500), never the client's fault (422). */
export function decodeStored<A, I>(
   schema: Schema.Schema<A, I, never>,
   input: unknown,
   context: string
): A {
   const result = Schema.decodeUnknownEither(schema)(input);
   if (Either.isLeft(result)) {
      throw new Error(`Stored data failed validation: ${context}.`, {
         cause: result.left,
      });
   }
   return result.right;
}
