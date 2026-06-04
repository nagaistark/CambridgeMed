import mongoose from 'mongoose';

/* 1. The Recursion Depth Limiter. A countdown tuple that forces TypeScript to stop traversing after a certain depth. */
type Prev = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/* 2. The Mongoose Leaf Guard. We use the list of primitives. When TypeScript hits any of these, it knows it has reached the "bottom" of a path and will not try to look inside them. (Note: RegExp added, as it is a standard built-in object often used in schemas). */
type MongoPrimitive =
   | string
   | number
   | boolean
   | Date
   | mongoose.Types.ObjectId
   | mongoose.Types.Decimal128
   | Buffer
   | RegExp;

// 3. The Path Generator
export type MongoIndexPaths<T, D extends number = 5> =
   // Safety: If we run out of depth, stop traversing.
   [D] extends [never]
      ? never
      : // Nullability: Strip undefined/null right away so optional fields don't break the chain.
        NonNullable<T> extends readonly (infer U)[]
        ? // Array Handling: If it's an array, look at the item inside it (U). We don't add an array index (like [0]), because Mongo indexes don't use them.
          MongoIndexPaths<U, D>
        : // Primitive Handling: If we hit a string, Date, ObjectId, etc., we stop.
          NonNullable<T> extends MongoPrimitive
          ? never
          : // Object Handling: If it's a standard object, map over its keys.
            NonNullable<T> extends object
            ? {
                 [K in keyof NonNullable<T> & string]:  // Yield the current path (allows for indexing intermediate sub-documents)
                    | K
                    // Recursively fetch nested paths, appending them with dot notation
                    | (MongoIndexPaths<
                         NonNullable<T>[K],
                         Prev[D]
                      > extends infer P
                         ? P extends never
                            ? never
                            : `${K}.${P & string}`
                         : never);
              }[keyof NonNullable<T> & string]
            : never;

// 4. The Mongoose Index Helper. To use this to enforce strict types on Mongoose `.index()` calls.
export type StrictIndexConfig<T> = Partial<
   Record<MongoIndexPaths<T>, 1 | -1 | 'text'>
>;
