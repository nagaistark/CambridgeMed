import logger from 'logger.ts';
import { createTypedIndexes } from '@utils/typedIndexDescription.ts';
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

export async function initializeDatabaseIndexes() {
   logger.info(`Ensuring database indexes...`);
   await createTypedIndexes(getAuditLogCollection(), auditLogIndexes);
   await createTypedIndexes(getInviteCollection(), inviteIndexes);
   await createTypedIndexes(getUserCollection(), userIndexes);
   await createTypedIndexes(getSessionCollection(), sessionIndexes);
   await createTypedIndexes(getPasswordResetCollection(), passwordResetIndexes);
   await createTypedIndexes(getEmailChangeCollection(), emailChangeIndexes);
   // Future collections will be added here...
   logger.info(`Database indexes ensured.`);
}
