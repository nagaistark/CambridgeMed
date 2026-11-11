import { env } from 'node:process';
import { MongoClient, type Collection, type Document } from 'mongodb';
import type { IAuditLogDoc } from '@models/AuditLog_v3.model.ts';
import type { ISecurityEventDocument } from '@models/SecurityEvent_v3.model.ts';
import {
   createTypedIndexes,
   type TypedIndexDescription,
} from '@utils/typedIndexDescription.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';

/* Run by a human, never by the app: `pnpm run db:indexes`. Needs DB_AUDIT_ADMIN_URI (the AuditMigrator user). That variable must NEVER be set in the Render dashboard. */

/* Explicit, not taken from the URI: a URI without a database name silently falls back to "test". If this name is wrong, Atlas answers with code 13 instead of creating anything. It must match the database in your DB_AUDIT_URI. */
const AUDIT_DB_NAME = 'audit' as const;

/* Names equal MongoDB's auto-generated ones, so existing indexes are recognised and nothing is rebuilt. */
const auditLogIndexes = [
   {
      name: 'patientIDs_1_occurredAt_-1',
      key: { patientIDs: 1, occurredAt: -1 },
   },
   { name: 'actorID_1_occurredAt_-1', key: { actorID: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<IAuditLogDoc>[];

/* Deliberately NO TTL index: retention is a compliance decision, not a default. */
const securityEventIndexes = [
   {
      name: 'targetUserId_1_occurredAt_-1',
      key: { targetUserId: 1, occurredAt: -1 },
   },
   { name: 'event_1_occurredAt_-1', key: { event: 1, occurredAt: -1 } },
   { name: 'actorId_1_occurredAt_-1', key: { actorId: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<ISecurityEventDocument>[];

function readAdminUri(): string {
   const uri = env['DB_AUDIT_ADMIN_URI'];
   if (typeof uri !== 'string' || uri.trim() === '') {
      throw new Error(`DB_AUDIT_ADMIN_URI is missing. Check .env.migrate.`);
   }
   return uri.trim();
}

async function reportIndexes<T extends Document>(
   collection: Collection<T>
): Promise<void> {
   const names = (await collection.listIndexes().toArray()).map(
      index => index.name
   );
   process.stdout.write(`${collection.collectionName}: ${names.join(', ')}\n`);
}

async function main(): Promise<void> {
   const client = new MongoClient(readAdminUri(), {
      appName: 'cambridgemed-migrations',
      serverSelectionTimeoutMS: 10_000,
   });

   try {
      await client.connect();
      const db = client.db(AUDIT_DB_NAME);
      process.stdout.write(`Connected to Audit\n`);
      const auditLogs = db.collection<IAuditLogDoc>('auditlogs');
      const securityEvents =
         db.collection<ISecurityEventDocument>('securityevents');

      await createTypedIndexes(auditLogs, auditLogIndexes);
      await createTypedIndexes(securityEvents, securityEventIndexes);

      await reportIndexes(auditLogs);
      await reportIndexes(securityEvents);
   } finally {
      await client.close();
   }
}

try {
   await main();
} catch (err) {
   process.stderr.write(
      `Index migration failed: ${sanitizeError(err).message}\n`
   );
   process.exitCode = 1;
}
