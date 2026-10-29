import type { ObjectId } from 'mongodb';
import { Either, Schema } from 'effect';
import {
   EmailChangeStatusSourceValidator,
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
   type IEmailChangeStatusSource,
} from '@models/EmailChange_v3.model.ts';
import {
   classifyEmailChange,
   type EmailChangeStatus,
} from '@ssot/email_change_status_constants.ts';
import { EMAIL_CHANGE_STATUS_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';

/* The unique `userId` index guarantees at most one document, so this is a single indexed point read. Read-only: safe to call before any commit point. */
export async function loadEmailChangeStatus(
   userId: ObjectId,
   now: Date
): Promise<EmailChangeStatus> {
   const changeRaw =
      await getEmailChangeCollection().findOne<IEmailChangeStatusSource>(
         { userId } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         {
            projection: EMAIL_CHANGE_STATUS_PROJECTION,
         } satisfies StrictFindOneOptions<IEmailChangeStatusSource>
      );

   if (changeRaw === null) return { state: 'none' };

   const decoded = Schema.decodeUnknownEither(EmailChangeStatusSourceValidator)(
      changeRaw
   );
   if (Either.isLeft(decoded)) {
      throw new Error(
         `Stored email change failed validation while reading its status.`,
         { cause: decoded.left }
      );
   }

   return classifyEmailChange(decoded.right, now);
}
