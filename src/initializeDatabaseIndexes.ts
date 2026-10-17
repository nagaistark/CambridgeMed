import logger from './logger.ts';
import {
   createTypedIndexes,
   type TypedIndexDescription,
} from '@utils/typedIndexDescription.ts';
import { getInviteCollection, inviteIndexes } from '@models/Invite_v3.model.ts';
import { getUserCollection, userIndexes } from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   sessionIndexes,
} from '@models/Session_v3.model.ts';
import {
   getPasswordResetCollection,
   passwordResetIndexes,
} from '@models/PasswordReset_v3.model.ts';
import {
   emailChangeIndexes,
   getEmailChangeCollection,
} from '@models/EmailChange_v3.model.ts';
import {
   auditLogIndexes,
   getAuditLogCollection,
} from '@models/AuditLog_v3.model.ts';
import { MongoServerError, type Collection, type Document } from 'mongodb';

/* MongoDB error codes for "an index with this name already exists, but with a different definition". */
const INDEX_OPTIONS_CONFLICT = 85 as const;
const INDEX_KEY_SPECS_CONFLICT = 86 as const;

async function ensureIndexes<T extends Document>(
   collection: Collection<T>,
   indexes: readonly TypedIndexDescription<T>[]
): Promise<void> {
   try {
      await createTypedIndexes(collection, indexes);
   } catch (err) {
      if (
         err instanceof MongoServerError &&
         (err.code === INDEX_OPTIONS_CONFLICT ||
            err.code === INDEX_KEY_SPECS_CONFLICT)
      ) {
         logger.error(
            `Index conflict on "${collection.collectionName}": an existing index has the same name but a different definition. Drop the stale index and restart.`
         );
      }
      throw err; // Still fatal: the server must not start with the wrong indexes.
   }
}

export async function initializeDatabaseIndexes(): Promise<void> {
   logger.info(`Ensuring database indexes...`);
   await ensureIndexes(getAuditLogCollection(), auditLogIndexes);
   await ensureIndexes(getInviteCollection(), inviteIndexes);
   await ensureIndexes(getUserCollection(), userIndexes);
   await ensureIndexes(getSessionCollection(), sessionIndexes);
   await ensureIndexes(getPasswordResetCollection(), passwordResetIndexes);
   await ensureIndexes(getEmailChangeCollection(), emailChangeIndexes);
   // Future collections will be added here...
   logger.info(`Database indexes ensured.`);
}
