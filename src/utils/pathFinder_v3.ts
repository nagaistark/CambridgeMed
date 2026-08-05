import type {
   ObjectId,
   Decimal128,
   Binary,
   Timestamp,
   IndexDirection,
   Condition,
   SortDirection,
   FindOptions,
   FindOneAndUpdateOptions,
   FindOneOptions,
   BSONType,
   BSONTypeAlias,
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
type MongoDocumentPaths<T, D extends number = 5> =
   /* Safety: If we run out of depth, stop traversing. */
   [D] extends [never]
      ? never
      : /* Nullability: Strip undefined/null right away so optional fields don't break the chain. */
        NonNullable<T> extends readonly (infer U)[]
        ? /* Array Handling: If it's an array, look at the item inside it (U). */
          MongoDocumentPaths<U, D>
        : /* Primitive Handling: If we hit a string, Date, ObjectId, etc., we stop. */
          NonNullable<T> extends MongoPrimitive
          ? never
          : /* Object Handling: If it's a standard object, map over its keys. */
            NonNullable<T> extends object
            ? {
                 [
                    K in keyof NonNullable<T> & string // Yield the current path
                 ]:
                    | K
                    /* Recursively fetch nested paths, appending them with dot notation */
                    | (MongoDocumentPaths<
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
   [K in MongoDocumentPaths<T>]?: IndexDirection;
};

// ─────────────────────────────────────────────────────────────────────────────────
/* Extracts the exact type of a value at a given MongoDocumentPaths dot-notation string. Mirrors the array-unwrapping and nullability-stripping logic of MongoDocumentPaths. P stands for "path" in case I ever forget this. */
export type MongoPathValue<T, P extends string> = P extends keyof NonNullable<T>
   ? NonNullable<T>[P]
   : P extends `${infer K}.${infer Rest}`
     ? K extends keyof NonNullable<T>
        ? NonNullable<T>[K] extends readonly (infer U)[]
           ? MongoPathValue<U, Rest>
           : MongoPathValue<NonNullable<T>[K], Rest>
        : never
     : never;

// ── STRICT FILTER OBJECT ─────────────────────────────────────────────────────────
type StrictFilterOperators<T> = {
   $eq?: T;
   $ne?: T;
   $gt?: T;
   $gte?: T;
   $lt?: T;
   $lte?: T;
   $in?: ReadonlyArray<T>;
   $nin?: ReadonlyArray<T>;
   $exists?: boolean;
   $type?: BSONType | BSONTypeAlias | number | string;
   $mod?: [number, number];
   $regex?: string | RegExp;
   $options?: string;
   $size?: T extends ReadonlyArray<any> ? number : never;
   $all?: T extends ReadonlyArray<infer U> ? ReadonlyArray<U> : never;
   $elemMatch?: T extends ReadonlyArray<infer U> ? StrictMongoFilter<U> : never;
};

type StrictCondition<T> = T | StrictFilterOperators<T>;

type StrictMongoFilterFields<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: StrictCondition<
      MongoPathValue<TSchema, P>
   >;
};

type StrictRootFilterOperators<TSchema> = {
   $and?: ReadonlyArray<StrictMongoFilter<TSchema>>;
   $or?: ReadonlyArray<StrictMongoFilter<TSchema>>;
   $nor?: ReadonlyArray<StrictMongoFilter<TSchema>>;
};

export type StrictMongoFilter<TSchema> = StrictMongoFilterFields<TSchema> &
   StrictRootFilterOperators<TSchema>;

// ── STRICT UPDATE OBJECT ─────────────────────────────────────────────────────────
/* Types for the "update" object */
type StrictSet<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: MongoPathValue<TSchema, P>;
};

type StrictUnset<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: '' | true | 1;
};

type NumericPaths<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]: MongoPathValue<TSchema, P> extends number
      ? P
      : never;
}[MongoDocumentPaths<TSchema>];

type StrictInc<TSchema> = {
   [P in NumericPaths<TSchema>]?: number;
};

type ArrayPaths<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]: MongoPathValue<
      TSchema,
      P
   > extends ReadonlyArray<any>
      ? P
      : never;
}[MongoDocumentPaths<TSchema>];

type ArrayElement<TSchema, P extends ArrayPaths<TSchema>> =
   MongoPathValue<TSchema, P> extends ReadonlyArray<infer U> ? U : never;

type StrictPush<TSchema> = {
   [P in ArrayPaths<TSchema>]?:
      | ArrayElement<TSchema, P>
      | { $each: ReadonlyArray<ArrayElement<TSchema, P>> };
};

export type StrictUpdate<TSchema> = {
   $set?: StrictSet<TSchema>;
   $unset?: StrictUnset<TSchema>;
   $inc?: StrictInc<TSchema>;
   $push?: StrictPush<TSchema>;
   $addToSet?: StrictPush<TSchema>;
};

// ── STRICT OPTIONS ───────────────────────────────────────────────────────────────
type StrictProjection<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: 0 | 1 | boolean;
};

type StrictSort<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: SortDirection;
};

export type StrictFindOptions<TSchema> = Omit<
   FindOptions,
   'projection' | 'sort'
> & {
   projection?: StrictProjection<TSchema>;
   sort?: StrictSort<TSchema>;
};

export type StrictFindOneOptions<TSchema> = Omit<
   FindOneOptions,
   'projection' | 'sort'
> & {
   projection?: StrictProjection<TSchema>;
   sort?: StrictSort<TSchema>;
};

export type StrictFindOneAndUpdateOptions<TSchema> = Omit<
   FindOneAndUpdateOptions,
   'projection' | 'sort'
> & {
   projection?: StrictProjection<TSchema>;
   sort?: StrictSort<TSchema>;
};
