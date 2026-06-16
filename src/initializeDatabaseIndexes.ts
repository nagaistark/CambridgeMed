import logger from 'logger.ts';
import { createTypedIndexes } from '@utils/typedIndexDescription.ts';
import { getInviteCollection, inviteIndexes } from '@models/Invite_v2.model.ts';

export async function initializeDatabaseIndexes() {
   logger.info(`Ensuring database indexes...`);
   await createTypedIndexes(getInviteCollection(), inviteIndexes);
   // Future collections will be added here...
   logger.info(`Database indexes ensured.`);
}
