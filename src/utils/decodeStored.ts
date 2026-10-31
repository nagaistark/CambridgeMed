import { Either, ParseResult, Schema } from 'effect';

/* A failure here is OUR fault (data drift or a bug), never the client's, so it
   must reach handleCatchAll (500) rather than handleParseError (422). */
export class StoredDataError extends Error {
   readonly invalidPaths: readonly string[];

   constructor(context: string, parseError: ParseResult.ParseError) {
      /* Paths only: ArrayFormatter messages can echo offending values (PHI). */
      const invalidPaths = ParseResult.ArrayFormatter.formatErrorSync(
         parseError
      ).map(issue => issue.path.map(String).join('.') || '(root)');

      super(
         `Stored data failed validation: ${context} [${invalidPaths.join(', ')}].`,
         { cause: parseError }
      );
      this.name = 'StoredDataError';
      this.invalidPaths = invalidPaths;
   }
}

export function decodeStored<A, I>(
   schema: Schema.Schema<A, I, never>,
   input: unknown,
   context: string
): A {
   const result = Schema.decodeUnknownEither(schema, { errors: 'all' })(input);
   if (Either.isLeft(result)) {
      throw new StoredDataError(context, result.left);
   }
   return result.right;
}
