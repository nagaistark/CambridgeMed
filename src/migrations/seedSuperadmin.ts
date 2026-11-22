// src/migrations/seedSuperadmin.ts
import { env } from 'node:process';
import { Either, ParseResult, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import { myEnv } from '../validateConfig.ts';
import { DatabaseService } from '../mongoDBConnect.ts';
import {
   UserDocumentValidator,
   UserInputSchema,
   userIndexes,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import { ROLE_SUPERADMIN } from '@ssot/user_roles_constants.ts';
import { resolvePermissions } from '@ssot/permissions_constants.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import { createTypedIndexes } from '@utils/typedIndexDescription.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

/* Run by a human, never by the app: `pnpm run db:seed-superadmin`.
   Credentials come from a throwaway, git-ignored `.env.seed` (delete it afterwards), never from argv, so they stay out of shell history and process listings. */

/* Same rules as registration: one definition, no drift. */
const decodeSeedInput = Schema.decodeUnknownEither(UserInputSchema, {
   errors: 'all',
   onExcessProperty: 'error',
});

function readSeedInput(): Schema.Schema.Type<typeof UserInputSchema> {
   const result = decodeSeedInput({
      firstName: env['SEED_SUPERADMIN_FIRST_NAME'],
      lastName: env['SEED_SUPERADMIN_LAST_NAME'],
      email: env['SEED_SUPERADMIN_EMAIL'],
      password: env['SEED_SUPERADMIN_PASSWORD'],
   });

   if (Either.isLeft(result)) {
      /* Paths and messages only: the raw values (a password!) are never echoed. */
      const lines = ParseResult.ArrayFormatter.formatErrorSync(result.left).map(
         issue => ` • [${issue.path.map(String).join('.')}] ${issue.message}`
      );
      throw new Error(`Invalid seed input:\n${lines.join('\n')}`);
   }
   return result.right;
}

async function main(): Promise<void> {
   const input = readSeedInput();

   const auth = new DatabaseService(myEnv.database.authUri, 'AuthDB');

   try {
      await auth.connect();
      const users = auth.db().collection<IUserDocument>('users');

      /* The unique email index is the final arbiter; make sure it exists even on a fresh database that the app has never booted against. */
      await createTypedIndexes(users, userIndexes);

      const existing = await users.countDocuments(
         { role: ROLE_SUPERADMIN } satisfies StrictMongoFilter<IUserDocument>,
         { limit: 1 }
      );
      if (existing > 0) {
         throw new Error(`A superadmin already exists. Nothing was written.`);
      }

      const now = new Date();

      const candidate: IUserDocument = {
         _id: new ObjectId(),
         firstName: input.firstName,
         lastName: input.lastName,
         email: input.email,
         passwordHash: await hashPassword(input.password),
         role: ROLE_SUPERADMIN,
         permissions: resolvePermissions(ROLE_SUPERADMIN, 0),
         previousNames: [],
         previousEmails: [],
         nameChangesUsed: 0,
         emailChangesUsed: 0,
         isTotpEnabled: false,
         totpSecret: null,
         totpPendingSecret: null,
         totpRecoveryCodes: [],
         totpLastUsedStep: 0,
         totpAttempts: 0,
         totpAttemptsWindowStartedAt: null,
         invitedBy: null,
         isActive: true,
         passwordResetRequired: false,
         credentialsVersion: 0,
         createdAt: now,
         updatedAt: now,
      };

      /* The whole point: the seed passes through the SAME gate as every read. */
      const validated = decodeStored(
         UserDocumentValidator,
         candidate,
         'seed superadmin'
      );

      try {
         await users.insertOne(validated);
      } catch (err) {
         if (isDuplicateKeyOnField(err, 'email')) {
            throw new Error(`A user with this email already exists.`, {
               cause: err,
            });
         }
         throw err;
      }

      process.stdout.write(
         `Superadmin created: ${validated.email} (${validated._id.toHexString()})\n`
      );
   } finally {
      await auth.shutdown();
   }
}

try {
   await main();
} catch (err) {
   process.stderr.write(`Seed failed: ${sanitizeError(err).message}\n`);
   process.exitCode = 1;
}
