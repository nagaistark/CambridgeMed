import { picklist } from 'valibot';

export function makePicklist<T extends readonly string[]>(arr: T) {
   return picklist(arr, `Must be one of the ${arr.join(', ')}`);
}
