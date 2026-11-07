const MONGO_URI_CREDENTIALS = /(mongodb(?:\+srv)?:\/\/)[^@/\s]+@/gi;

const sanitizeString = (str: string): string =>
   str.replace(MONGO_URI_CREDENTIALS, '$1****:****@');

export function sanitizeError(input: unknown): {
   message: string;
   stack?: string;
} {
   if (typeof input === 'string') {
      return { message: sanitizeString(input) };
   }

   if (input instanceof Error) {
      return {
         message: sanitizeString(input.message || 'Unknown Error'),
         stack: input.stack ? sanitizeString(input.stack) : undefined,
      };
   }

   if (input !== null && typeof input === 'object' && 'message' in input) {
      if (typeof input.message === 'string') {
         return { message: sanitizeString(input.message) };
      }
   }

   return { message: 'Unknown Error' };
}
