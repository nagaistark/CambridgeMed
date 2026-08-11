import type {
   ObjectId,
   Decimal128,
   Binary,
   Timestamp,
   IndexDirection,
   SortDirection,
   FindOptions,
   FindOneAndUpdateOptions,
   FindOneOptions,
   BSONType,
   BSONTypeAlias,
   Long,
} from 'mongodb';

/* 1. The Recursion Depth Limiter. */
type Prev = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/* 2. BSON & Scalar Leaf Guard */
type MongoLeaf =
   | string
   | number
   | boolean
   | Date
   | ObjectId
   | Decimal128
   | Binary
   | Timestamp
   | Long
   | Buffer
   | RegExp
   | bigint
   | symbol;

/* 3. Document Paths for Queries, Indexes, and Projections */
export type MongoDocumentPaths<T, D extends number = 5> =
   /* Safety: If we run out of depth, stop traversing. */
   [D] extends [never]
      ? never
      : /* Nullability: Strip undefined/null right away so optional fields don't break the chain. */
        NonNullable<T> extends readonly (infer U)[]
        ? /* Array Handling: If it's an array, look at the item inside it (U). */
          MongoDocumentPaths<U, D>
        : /* Primitive Handling: If we hit a string, Date, ObjectId, etc., we stop. */
          NonNullable<T> extends MongoLeaf
          ? never
          : DistributeObjectPaths<NonNullable<T>, D>;

type DistributeObjectPaths<T, D extends number> = T extends unknown
   ? {
        [K in keyof T & string]:
           | K
           | (MongoDocumentPaths<T[K], Prev[D]> extends infer P
                ? P extends never
                   ? never
                   : `${K}.${P & string}`
                : never);
     }[keyof T & string]
   : never;

/* 3.1 Document Paths for Updates (Handles array operators for objects AND primitives) */
export type MongoUpdatePaths<T, D extends number = 5> = [D] extends [never]
   ? never
   : NonNullable<T> extends MongoLeaf
     ? never
     : DistributeUpdatePaths<NonNullable<T>, D>;

type DistributeUpdatePaths<T, D extends number> = T extends unknown
   ? {
        [K in keyof T & string]:
           | K
           | (NonNullable<T[K]> extends readonly (infer U)[]
                ? | `${K}.${'$' | '$[]' | `${number}`}`
                  | (MongoUpdatePaths<U, Prev[D]> extends infer P
                       ? P extends never
                          ? never
                          : `${K}.${'$' | '$[]' | `${number}`}.${P & string}`
                       : never)
                : MongoUpdatePaths<T[K], Prev[D]> extends infer P
                  ? P extends never
                     ? never
                     : `${K}.${P & string}`
                  : never);
     }[keyof T & string]
   : never;

/* 4. Index Configuration */
export type StrictIndexConfig<T> = {
   [K in MongoDocumentPaths<T>]?: IndexDirection;
};

// ── PATH VALUE EXTRACTORS ────────────────────────────────────────────────────────
type MongoQueryPathValue<T, P extends string> = T extends unknown
   ? P extends keyof NonNullable<T>
      ? NonNullable<T>[P]
      : P extends `${infer K}.${infer Rest}`
        ? K extends keyof NonNullable<T>
           ? NonNullable<NonNullable<T>[K]> extends readonly (infer U)[]
              ? MongoQueryPathValue<U, Rest>
              : MongoQueryPathValue<NonNullable<NonNullable<T>[K]>, Rest>
           : never
        : never
   : never;

type MongoArraySelector = '$' | '$[]' | `$[${string}]` | `${number}`;

type MongoUpdatePathValue<T, P extends string> = T extends unknown
   ? P extends keyof NonNullable<T>
      ? NonNullable<T>[P]
      : P extends `${infer K}.${infer Rest}`
        ? K extends keyof NonNullable<T>
           ? NonNullable<NonNullable<T>[K]> extends readonly (infer U)[]
              ? Rest extends `${MongoArraySelector}.${infer Nested}`
                 ? MongoUpdatePathValue<U, Nested>
                 : Rest extends MongoArraySelector
                   ? U
                   : never
              : MongoUpdatePathValue<NonNullable<NonNullable<T>[K]>, Rest>
           : never
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
   $in?: ReadonlyArray<
      NonNullable<T> extends ReadonlyArray<infer U> ? U : NonNullable<T>
   >;
   $nin?: ReadonlyArray<
      NonNullable<T> extends ReadonlyArray<infer U> ? U : NonNullable<T>
   >;
   $exists?: boolean;
   $type?: BSONType | BSONTypeAlias;
   $mod?: NonNullable<T> extends number ? [number, number] : never;
   $regex?: NonNullable<T> extends string ? string | RegExp : never;
   $options?: NonNullable<T> extends string | RegExp ? string : never;
   $size?: NonNullable<T> extends ReadonlyArray<any> ? number : never;
   $all?: NonNullable<T> extends ReadonlyArray<infer U>
      ? ReadonlyArray<U>
      : never;
   $elemMatch?: NonNullable<T> extends ReadonlyArray<infer U>
      ? NonNullable<U> extends MongoLeaf
         ? StrictFilterOperators<U> | U
         : StrictMongoFilter<U>
      : never;
   $not?:
      | StrictFilterOperators<T>
      | (NonNullable<T> extends string ? RegExp : never);
};

type StrictCondition<T> =
   T extends ReadonlyArray<infer U>
      ? T | U | StrictFilterOperators<T> | StrictFilterOperators<U>
      : T | StrictFilterOperators<T>;

type StrictMongoFilterFields<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: StrictCondition<
      MongoQueryPathValue<TSchema, P>
   >;
};

type StrictRootFilterOperators<TSchema> = {
   $and?: ReadonlyArray<StrictMongoFilter<TSchema>>;
   $or?: ReadonlyArray<StrictMongoFilter<TSchema>>;
   $nor?: ReadonlyArray<StrictMongoFilter<TSchema>>;
   $expr?: Record<string, any>;
};

export type StrictMongoFilter<TSchema> = StrictMongoFilterFields<TSchema> &
   StrictRootFilterOperators<TSchema>;

// ── STRICT UPDATE OBJECT ─────────────────────────────────────────────────────────
type StrictSet<TSchema> = {
   [P in MongoUpdatePaths<TSchema>]?: MongoUpdatePathValue<TSchema, P>;
};

type StrictUnset<TSchema> = {
   [P in MongoUpdatePaths<TSchema>]?: '' | true | 1;
};

type NumericPaths<TSchema> = {
   [P in MongoUpdatePaths<TSchema>]: MongoUpdatePathValue<
      TSchema,
      P
   > extends number
      ? P
      : never;
}[MongoUpdatePaths<TSchema>];

type StrictInc<TSchema> = {
   [P in NumericPaths<TSchema>]?: number;
};

type MongoArrayFields<TSchema> = {
   [P in MongoUpdatePaths<TSchema>]: NonNullable<
      MongoUpdatePathValue<TSchema, P>
   > extends ReadonlyArray<any>
      ? P
      : never;
}[MongoUpdatePaths<TSchema>];

type ArrayElement<TSchema, P extends MongoArrayFields<TSchema>> =
   NonNullable<MongoUpdatePathValue<TSchema, P>> extends ReadonlyArray<infer U>
      ? U
      : never;

type PushEachModifier<U> = {
   $each: ReadonlyArray<U>;
   $position?: number;
   $slice?: number;
   $sort?: 1 | -1 | Record<string, 1 | -1>;
};

type StrictPush<TSchema> = {
   [P in MongoArrayFields<TSchema>]?:
      ArrayElement<TSchema, P> | PushEachModifier<ArrayElement<TSchema, P>>;
};

/* $addToSet only supports the bare $each modifier -- $position/$slice/$sort are $push-only and are invalid MongoDB syntax for $addToSet. */
type AddToSetEachModifier<U> = {
   $each: ReadonlyArray<U>;
};

type StrictAddToSet<TSchema> = {
   [P in MongoArrayFields<TSchema>]?:
      ArrayElement<TSchema, P> | AddToSetEachModifier<ArrayElement<TSchema, P>>;
};

type StrictPull<TSchema> = {
   [P in MongoArrayFields<TSchema>]?: NonNullable<
      ArrayElement<TSchema, P>
   > extends MongoLeaf
      ? StrictCondition<ArrayElement<TSchema, P>>
      : StrictMongoFilter<ArrayElement<TSchema, P>>;
};

export type StrictUpdate<TSchema> = {
   $set?: StrictSet<TSchema>;
   $setOnInsert?: StrictSet<TSchema>;
   $unset?: StrictUnset<TSchema>;
   $inc?: StrictInc<TSchema>;
   $mul?: StrictInc<TSchema>;
   $min?: StrictSet<TSchema>;
   $max?: StrictSet<TSchema>;
   $push?: StrictPush<TSchema>;
   $pull?: StrictPull<TSchema>;
   $addToSet?: StrictAddToSet<TSchema>;
   $pop?: { [P in MongoArrayFields<TSchema>]?: 1 | -1 };
   $rename?: { [P in MongoUpdatePaths<TSchema>]?: string };
};

// ── STRICT OPTIONS ───────────────────────────────────────────────────────────────
type ProjectionValue<T> =
   | 0
   | 1
   | boolean
   | { $slice: number | [number, number] }
   | { $meta: string }
   | (NonNullable<T> extends ReadonlyArray<infer U>
        ? {
             $elemMatch: NonNullable<U> extends MongoLeaf
                ? StrictFilterOperators<U>
                : StrictMongoFilter<U>;
          }
        : never);

type StrictProjection<TSchema> = {
   [P in MongoDocumentPaths<TSchema>]?: ProjectionValue<
      MongoQueryPathValue<TSchema, P>
   >;
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
