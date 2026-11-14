import '@ssot/date_time_constants.ts';
import app from './app.ts';
import { createServer, type Server } from 'node:http';
import { myEnv } from './validateConfig.ts';
import logger from './logger.ts';

import { DatabaseManager } from './mongoDBConnect.ts';
import { handleGracefulShutdown } from './shutdown.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import { initializeDatabaseIndexes } from './initializeDatabaseIndexes.ts';

// ===== GLOBAL PROCESS LISTENERS (Must be first!) =================================
process.on('uncaughtException', (error: Error) => {
   const sanitized = sanitizeError(error);
   logger.error(
      `Uncaught Exception! Critical failure:\n${sanitized.message}\n${sanitized.stack}`
   );
   process.exit(1);
});

process.on('unhandledRejection', (reason: unknown) => {
   // Normalizing to an Error so that the `uncaughtException` handler always gets a proper stack
   const error =
      reason instanceof Error
         ? reason
         : new Error(`Unhandled Rejection: ${String(reason)}`);
   logger.error(`Unhandled Rejection:\n${error.stack}`);
   throw error;
});

// ===== PORT & HOST ===============================================================
const port: number = myEnv.server.port;
const host: string = myEnv.server.host;

// ===== SERVER BOOTSTRAP ==========================================================
/* The order of operations:
   Step 1 — Database: network I/O, slow, pointless if Step 1 failed
   Step 2 — Database: ensuring indexes
   Step 3 — HTTP server: no point listening for requests until Steps 1 & 2 pass */
let server: Server | undefined;

const startServer = async (): Promise<void> => {
   try {
      logger.info(`Starting server bootstrap...`);

      // Step 1: Connecting to the database
      const dbManager = DatabaseManager.getInstance();
      await dbManager.initialize();

      // Step 2: Ensuring indexes
      await initializeDatabaseIndexes();

      // Step 3: Starting the HTTP server
      const listening = await new Promise<Server>((resolve, reject) => {
         const s = createServer(
            {
               keepAliveTimeout: 80_000,
               headersTimeout: 30_000,
               requestTimeout: 30_000,
            },
            app
         );
         s.once('error', reject);
         s.listen(port, host, () => resolve(s));
      });
      server = listening;

      /* Set immediately after listen, before any connections arrive. */
      listening.keepAliveTimeout = 80_000; // Must exceed Render's timeout value
      listening.headersTimeout = 81_000; // Must exceed keepAliveTimeout
      listening.requestTimeout = 30_000; // Slowloris defence
      listening.timeout = 0; // Disabling the legacy socket inactivity timer...

      /* After a successful listen, `once('error', reject)` is a dead end. Post-listen errors need a real listener. */
      listening.on('error', error => {
         logger.error(`HTTP server error: ${sanitizeError(error).message}`);
      });

      logger.info(`Server running at http://${host}:${port}`);
      logger.info(`Keep-alive timeout: ${server.keepAliveTimeout}ms`);
   } catch (error) {
      // All four steps funnel into single `catch` block.
      const sanitized = sanitizeError(error);
      logger.error(`Fatal startup error: ${sanitized.stack}`);

      // Calling `cleanup` is safe even if the DB never connected.
      await DatabaseManager.getInstance().cleanup();
      process.exit(1);
   }
};

const onShutdownSignal = (signal: 'SIGINT' | 'SIGTERM') => {
   if (!server) {
      logger.warn(
         `${signal} received during startup. Cleaning up and exiting.`
      );
      DatabaseManager.getInstance()
         .cleanup()
         .then(() => process.exit(process.exitCode ?? 0))
         .catch(() => process.exit(1));
      return;
   }
   handleGracefulShutdown(server, signal).catch(error => {
      const sanitized = sanitizeError(error);
      logger.error(`Graceful shutdown failed: ${sanitized.stack}`);
      process.exit(1);
   });
};

process.on('SIGINT', () => onShutdownSignal('SIGINT'));
process.on('SIGTERM', () => onShutdownSignal('SIGTERM'));

void startServer();
