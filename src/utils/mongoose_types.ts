import mongoose from 'mongoose';

export type StrictSchemaDefinition<T> = {
   [K in keyof T]-?: mongoose.SchemaDefinitionProperty<NonNullable<T[K]>>;
};

/* Don't hate the exclusion list. Best I can do to filter out plain, user-defined object shapes. Notice that we explicitly exclude types that Mongoose treats as first-class primitives despite being objects in the JavaScript/TypeScript sense. */
type IsPlainObject<T> = T extends
   | Date
   | mongoose.Types.ObjectId
   | mongoose.Types.Decimal128
   | Buffer
   | Map<any, any>
   | Set<any>
   | WeakMap<object, any>
   | WeakSet<object>
   | Promise<any>
   | RegExp
   | ((...args: any[]) => any)
   | any[]
   | ReadonlyArray<any>
   ? false
   : T extends object
     ? true
     : false;

// v4
type RequiredProperty = boolean | [boolean, string];

type ResolveArrayField<U> =
   IsPlainObject<NonNullable<U>> extends true
      ? mongoose.Schema<NonNullable<U>>[]
      : mongoose.SchemaDefinitionProperty<NonNullable<U>>[];

type MongooseFieldDef_v4<T> =
   NonNullable<T> extends (infer U)[]
      ? // Array Branch: Allow bare array OR expanded descriptor object
           | ResolveArrayField<U>
           | {
                type: ResolveArrayField<U>;
                required?: RequiredProperty;
                default?: any[] | ((...args: any[]) => any[]);
             }
      : // Scalar Branch:
        IsPlainObject<NonNullable<T>> extends true
        ?
             | mongoose.Schema<NonNullable<T>>
             | {
                  type: mongoose.Schema<NonNullable<T>>;
                  required?: RequiredProperty;
                  default?: undefined;
               }
        : mongoose.SchemaDefinitionProperty<NonNullable<T>>;

export type StrictSchemaDefinition_v4<T> = {
   [K in keyof T]-?: MongooseFieldDef_v4<T[K]>;
};

/* The set of value types that Mongoose treats as atomic — i.e., types we should NOT recurse into when generating projection paths. Without this guard, TypeScript would try to descend into the internal properties of Date, ObjectId, etc., and produce nonsensical paths like '_id.id' or 'createdAt.valueOf'. */
type MongoPrimitive =
   | string
   | number
   | boolean
   | null
   | undefined
   | Date
   | mongoose.Types.ObjectId
   | mongoose.Types.Decimal128
   | Buffer;

/* Generates the union of all leaf-level dot-notation paths for a given type. "Leaf" means the field's resolved value type is either a MongoPrimitive or an array — in both cases we emit the path for that field and stop recursing. Arrays are intentionally treated as atomic because MongoDB path semantics for array elements differ from plain object nesting. Apply this to a lean response type to derive the exact Record key set for an inclusion projection, keeping the projection constraint automatically in sync with the type it represents. */
export type LeafPaths<T extends object, Prefix extends string = ''> = {
   [K in keyof T & string]: NonNullable<T[K]> extends readonly unknown[]
      ? `${Prefix}${K}` // array: atomic leaf — don't recurse
      : NonNullable<T[K]> extends MongoPrimitive
        ? `${Prefix}${K}` // primitive: leaf
        : NonNullable<T[K]> extends object
          ? LeafPaths<NonNullable<T[K]>, `${Prefix}${K}.`> // plain object: recurse
          : `${Prefix}${K}`;
}[keyof T & string];

// vX
type ExactMongooseType<T> = T extends string
   ? StringConstructor
   : T extends number
     ? NumberConstructor
     : T extends boolean
       ? BooleanConstructor
       : T extends Date
         ? DateConstructor
         : T extends mongoose.Types.ObjectId
           ? typeof mongoose.Schema.Types.ObjectId
           : T extends mongoose.Types.Decimal128
             ? typeof mongoose.Schema.Types.Decimal128
             : T extends Buffer
               ? typeof mongoose.Schema.Types.Buffer
               : mongoose.SchemaDefinitionProperty<T>; // Fallback only for complex/unknown types

type ResolveArrayFieldX<U> =
   IsPlainObject<NonNullable<U>> extends true
      ? [mongoose.Schema<NonNullable<U>>]
      : [ExactMongooseType<NonNullable<U>>];

type MongooseFieldDef_vX<T> =
   NonNullable<T> extends (infer U)[]
      ? // Array Branch
           | ResolveArrayFieldX<U>
           | {
                type: ResolveArrayFieldX<U>;
                required?: RequiredProperty;
                default?: any[] | ((...args: any[]) => any[]);
             }
      : // Scalar Branch
        IsPlainObject<NonNullable<T>> extends true
        ?
             | mongoose.Schema<NonNullable<T>>
             | {
                  type: mongoose.Schema<NonNullable<T>>;
                  required?: RequiredProperty;
                  default?: undefined;
               }
        : // Scalar Primitive
             | ExactMongooseType<NonNullable<T>>
             | {
                  type: ExactMongooseType<NonNullable<T>>;
                  required?: RequiredProperty;
                  default?: any;
               };

export type StrictSchemaDefinition_vX<T> = {
   [K in keyof T]-?: MongooseFieldDef_vX<T[K]>;
};

// v5
type RequiredProperty_ = boolean | [boolean, string];

// 1. STRICT MAP: Explicitly bind TS primitives to Mongoose constructors. This prevents Mongoose's generic "Function" type from allowing things like [Boolean] for ObjectIds.
type StrictTypeMap<T> =
   NonNullable<T> extends mongoose.Types.ObjectId
      ? typeof mongoose.Schema.Types.ObjectId
      : NonNullable<T> extends mongoose.Types.Decimal128
        ? typeof mongoose.Schema.Types.Decimal128
        : NonNullable<T> extends string
          ? typeof String | typeof mongoose.Schema.Types.String
          : NonNullable<T> extends number
            ? typeof Number | typeof mongoose.Schema.Types.Number
            : NonNullable<T> extends boolean
              ? typeof Boolean | typeof mongoose.Schema.Types.Boolean
              : NonNullable<T> extends Date
                ? typeof Date | typeof mongoose.Schema.Types.Date
                : NonNullable<T> extends Buffer
                  ? typeof Buffer | typeof mongoose.Schema.Types.Buffer
                  : IsPlainObject<NonNullable<T>> extends true
                    ?
                         | mongoose.Schema<NonNullable<T>>
                         | StrictSchemaDefinition_v5<NonNullable<T>>
                    : mongoose.SchemaDefinitionProperty<T>;

// 2. FIELD DEFINITION: Merge our strict 'type' with Mongoose's native options.
type MongooseFieldDef_v5<T> =
   NonNullable<T> extends (infer U)[]
      ? // Array Branch
           | StrictTypeMap<U>[]
           | [StrictTypeMap<U>]
           | (Omit<mongoose.SchemaTypeOptions<U[]>, 'type' | 'required'> & {
                type: StrictTypeMap<U>[] | [StrictTypeMap<U>];
                required?: RequiredProperty_;
             })
      : // Scalar Branch
           | StrictTypeMap<T>
           | (Omit<
                mongoose.SchemaTypeOptions<NonNullable<T>>,
                'type' | 'required'
             > & {
                type: StrictTypeMap<T>;
                required?: RequiredProperty_;
             });

// 3. THE SCHEMA DEFINITION
export type StrictSchemaDefinition_v5<T> = {
   [K in keyof T]-?: MongooseFieldDef_v5<T[K]>;
};
