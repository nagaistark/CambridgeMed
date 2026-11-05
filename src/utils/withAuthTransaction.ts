import type { ClientSession, TransactionOptions } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

const AUTH_TRANSACTION_OPTIONS: TransactionOptions = {
   readConcern: { level: 'snapshot' },
   writeConcern: { w: 'majority' },
   readPreference: 'primary', // required by transactions; stated so nobody "tunes" it
};

/* One place that owns "get client → start session → run transaction → ALWAYS end session". `work` may be invoked more than once (the driver retries transient errors), so it must keep all its state local. Throwing from `work` aborts and rolls back everything it wrote. */
export async function withAuthTransaction<T>(
   work: (session: ClientSession) => Promise<T>
): Promise<T> {
   const client = DatabaseManager.getInstance().auth.client;
   if (client === null) {
      throw new Error(`Auth database connection unavailable.`);
   }

   const session = client.startSession();
   try {
      return await session.withTransaction(
         () => work(session),
         AUTH_TRANSACTION_OPTIONS
      );
   } finally {
      await session.endSession();
   }
}
