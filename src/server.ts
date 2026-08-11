import '@ssot/date_time_constants.ts';
import app from './app.ts';
import { Server } from 'node:http';
import { myEnv } from './validateConfig.ts';
import { validateJwtKeys } from '@utils/jwtUtils.ts';
import logger from './logger.ts';

import {
   DatabaseManager,
   handleGracefulShutdown,
   sanitizeError,
} from './mongoDBConnect.ts';
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
   Step 1 — JWT keys: pure memory, instant, cheap to check
   Step 2 — Database: network I/O, slow, pointless if Step 1 failed
   Step 3 — Database: ensuring indexes
   Step 4 — HTTP server: no point listening for requests until Steps 1 & 2 pass */
let server!: Server;

const startServer = async (): Promise<void> => {
   try {
      logger.info(`Starting server bootstrap...`);

      // Step 1: Validating JWT key pair
      logger.info(`Validating JWT key pair...`);
      await validateJwtKeys();
      logger.info(`JWT key pair validated successfully`);

      // Step 2: Connecting to the database
      const dbManager = DatabaseManager.getInstance();
      await dbManager.initialize();

      // Step 3: Ensuring indexes
      await initializeDatabaseIndexes();

      // Step 4: Starting the HTTP server
      server = await new Promise<Server>((resolve, reject) => {
         const s = app.listen(port, host, () => resolve(s));
         s.once('error', reject);
      });

      // Set immediately after listen, before any connection arrive
      server.keepAliveTimeout = 80_000; // Must exceed Render's timeout value
      server.headersTimeout = 81_000; // Must exceed keepAliveTimeout
      server.requestTimeout = 30_000; // Kills the socket if the full incoming request (headers + body) isn't received within 30s. Our defence against against Slowloris-style attacks.
      server.timeout = 0; // Disabling the legacy socket inactivity timer...

      logger.info(`Server running at http://${host}:${port}`);
      logger.info(`Keep-alive timeout: ${server.keepAliveTimeout}ms`);
   } catch (error) {
      // All three steps funnel into single `catch` block.
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
         .then(() => process.exit(0))
         .catch(() => process.exit(1));
      return;
   }
   handleGracefulShutdown(server, signal).catch(error => {
      const sanitized = sanitizeError(error);
      logger.error(`Graceful shutdown failed: ${sanitized.stack}`);
      process.exit(1);
   });
};

process.once('SIGINT', () => onShutdownSignal('SIGINT'));
process.once('SIGTERM', () => onShutdownSignal('SIGTERM'));

void startServer();
