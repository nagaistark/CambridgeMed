import mongoose from 'mongoose';

export function createModelGetter<TDocument>(
   getConnection: () => mongoose.Connection | null,
   modelName: string,
   schema: mongoose.Schema<TDocument>
): () => mongoose.Model<TDocument> {
   let cached: mongoose.Model<TDocument> | null = null;

   return function (): mongoose.Model<TDocument> {
      if (cached) return cached;

      const connection = getConnection();
      if (!connection) {
         throw new Error(
            `${modelName} model requested before its database connection was established.`
         );
      }

      cached = connection.model<TDocument>(modelName, schema);
      return cached;
   };
}
