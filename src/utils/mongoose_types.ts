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

/* Valibot-inferred field type → Mongoose representation:
   plain object → mongoose.Schema<T> (a first-class Schema instance)
   array of objects → mongoose.Schema<U>[] (single-element array, e.g. [AddressSchema])
   array of primitives → SchemaDefinitionProperty<U>[]
   primitive → SchemaDefinitionProperty<T>

   NonNullable<T> strips the `| undefined` that Valibot's optional() adds. */
type MongooseFieldDef<T> =
   NonNullable<T> extends (infer U)[]
      ? IsPlainObject<NonNullable<U>> extends true
         ? mongoose.Schema<NonNullable<U>>[]
         : mongoose.SchemaDefinitionProperty<NonNullable<U>>[]
      : IsPlainObject<NonNullable<T>> extends true
        ? mongoose.Schema<NonNullable<T>>
        : mongoose.SchemaDefinitionProperty<NonNullable<T>>;

export type StrictSchemaDefinition_v2<T> = {
   [K in keyof T]-?: MongooseFieldDef<T[K]>;
};

// v3
type MongooseFieldDef_v3<T> =
   NonNullable<T> extends (infer U)[]
      ? IsPlainObject<NonNullable<U>> extends true
         ? mongoose.Schema<NonNullable<U>>[]
         : mongoose.SchemaDefinitionProperty<NonNullable<U>>[]
      : IsPlainObject<NonNullable<T>> extends true
        ? // Allow either a bare Schema or a wrapped descriptor with `type: Schema`
             | mongoose.Schema<NonNullable<T>>
             | {
                  type: mongoose.Schema<NonNullable<T>>;
                  required?: boolean;
                  default?: undefined;
               }
        : mongoose.SchemaDefinitionProperty<NonNullable<T>>;

export type StrictSchemaDefinition_v3<T> = {
   [K in keyof T]-?: MongooseFieldDef_v3<T[K]>;
};

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
