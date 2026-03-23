import mongoose from 'mongoose';

export type StrictSchemaDefinition<T> = {
   [K in keyof T]-?: mongoose.SchemaDefinitionProperty<T[K]>;
};
