import type {
   ObjectId,
   Decimal128,
   Binary,
   Timestamp,
   IndexDirection,
} from 'mongodb';

/* 1. The Recursion Depth Limiter. */
type Prev = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/* 2. The Native BSON Leaf Guard featuring native driver BSON types. Added Binary and Timestamp just in case Valibot schemas output them. */
type MongoPrimitive =
   | string
   | number
   | boolean
   | Date
   | ObjectId
   | Decimal128
   | Binary
   | Timestamp
   | Buffer
   | RegExp;

/* 3. The Path Generator. */
export type MongoIndexPaths<T, D extends number = 5> =
   /* Safety: If we run out of depth, stop traversing. */
   [D] extends [never]
      ? never
      : /* Nullability: Strip undefined/null right away so optional fields don't break the chain. */
        NonNullable<T> extends readonly (infer U)[]
        ? /* Array Handling: If it's an array, look at the item inside it (U). */
          MongoIndexPaths<U, D>
        : /* Primitive Handling: If we hit a string, Date, ObjectId, etc., we stop. */
          NonNullable<T> extends MongoPrimitive
          ? never
          : /* Object Handling: If it's a standard object, map over its keys. */
            NonNullable<T> extends object
            ? {
                 [K in keyof NonNullable<T> & string]:  // Yield the current path
                    | K
                    /* Recursively fetch nested paths, appending them with dot notation */
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

/* 4. Strict config utilizing MongoDB's native IndexDirection types. */
export type StrictIndexConfig<T> = {
   [K in MongoIndexPaths<T>]?: IndexDirection;
};

/* 5. A more universal path mapping helper */
export type PathMap<T, V> = {
   [K in MongoIndexPaths<T>]?: V;
};

// ── Tool that preserves the exact optionality structure of original type ─────────
/* 1. Extract keys that are strictly required */
export type RequiredKeys<T> = {
   [K in keyof T]-?: Pick<T, K> extends Required<Pick<T, K>> ? K : never;
}[keyof T];

/* 2. Extract keys that are optional */
export type OptionalKeys<T> = Exclude<keyof T, RequiredKeys<T>>;

/* 3. A standard utility to flatten intersecting types for clean IDE hover hints */
export type Prettify<T> = { [K in keyof T]: T[K] } & {};

/* 4. Safety Guard: Prevents mapping over arrays or native globals if passed by mistake. (MongoPrimitive is removed here to avoid the empty interface trap where unresolved types degrade to {} and swallow valid objects). */
type ValidObjectTarget<T> =
   NonNullable<T> extends readonly unknown[] | Date | RegExp
      ? never
      : NonNullable<T>;

/* 5. The PathMap that preserves the optionality structure (Shallow, NO dot notation) */
export type PathMap_PresOpt<T, V> = Prettify<
   { [K in RequiredKeys<ValidObjectTarget<T>>]: V } & {
      [K in OptionalKeys<ValidObjectTarget<T>>]?: V;
   }
>;

// ── The "All Required" Configuration Map ─────────────────────────────────────────

/* Makes all immediate keys strictly required (Shallow, NO dot notation) */
export type PathMap_AllReq<T, V> = Prettify<{
   [K in keyof ValidObjectTarget<T>]-?: V; // The -? modifier strips optionality
}>;
