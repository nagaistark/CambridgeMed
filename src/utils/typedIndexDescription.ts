import {
   Collection,
   Document,
   IndexDescription,
   IndexDirection,
} from 'mongodb';
import { StrictIndexConfig } from '@utils/pathFinder_v3.ts';

export type TypedIndexDescription<T> = Omit<IndexDescription, 'key'> & {
   key: StrictIndexConfig<T>;
};

export async function createTypedIndexes<T extends Document>(
   collection: Collection<T>,
   indexes: readonly TypedIndexDescription<T>[]
): Promise<string[]> {
   if (indexes.length === 0) return [];

   const nativeIndexes: IndexDescription[] = indexes.map(idx => {
      /* 1. Establish an empty object with the explicit signature MongoDB expects. */
      const baseRecord: Record<string, IndexDirection> = {};

      /* 2. Use Object.assign to natively intersect the loose record with your strict keys. TypeScript infers `nativeKey` as: Record<string, IndexDirection> & StrictIndexConfig<T> */
      const nativeKey = Object.assign(baseRecord, idx.key);

      /* 3. Assemble the final object. Because nativeKey inherently possesses the string index signature from Step A, this seamlessly assigns to IndexDescription. */
      const nativeIndex: IndexDescription = {
         ...idx,
         key: nativeKey,
      };

      return nativeIndex;
   });

   return collection.createIndexes(nativeIndexes);
}
