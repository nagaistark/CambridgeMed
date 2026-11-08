import type { Server } from 'node:http';
import logger from './logger.ts';
import { DatabaseManager } from './mongoDBConnect.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import { drainBackgroundTasks } from '@utils/backgroundTasks.ts';

/* Module-level sentinel prevents duplicate handling. */
let isShutdownCalled = false;

export const isShuttingDown = (): boolean => isShutdownCalled;

/*
   Used in server.ts via:
   process.once('SIGINT',  () => handleGracefulShutdown(server, 'SIGINT'));
   process.once('SIGTERM', () => handleGracefulShutdown(server, 'SIGTERM'));
*/

export const handleGracefulShutdown = async (
   server: Server,
   signal: 'SIGINT' | 'SIGTERM'
): Promise<void> => {
   if (isShutdownCalled) {
      logger.warn(`Shutdown already in progress. Ignoring duplicate signal.`);
      return;
   }
   isShutdownCalled = true;

   logger.info(`[${signal}] Initiating graceful exit...`);

   const forceQuit = setTimeout(() => {
      logger.error(`Shutdown timed out. Forcing exit...`);
      server.closeAllConnections();
      process.exit(1);
   }, 10000).unref();

   let hasErrorDuringShutdown = false;

   try {
      /* Step 1: stop accepting traffic. */
      try {
         await new Promise<void>((resolve, reject) => {
            server.close(err => (err ? reject(err) : resolve()));
            server.closeIdleConnections();
         });
         logger.info(`HTTP server closed.`);
      } catch (serverError) {
         hasErrorDuringShutdown = true;
         logger.error(
            `Error closing HTTP server: ${sanitizeError(serverError).message}`
         );
      }

      /* Step 2: let fire-and-forget audit/security/email work finish BEFORE the databases close. */
      await drainBackgroundTasks();

      /* Step 3: close database connections. */
      await DatabaseManager.getInstance().cleanup();
      logger.info(`Database connections closed.`);

      clearTimeout(forceQuit);
      logger.info(`Graceful shutdown complete.`);

      process.exit(hasErrorDuringShutdown ? 1 : (process.exitCode ?? 0));
   } catch (error) {
      logger.error(`Error during shutdown: ${sanitizeError(error).message}`);
      process.exit(1);
   }
};
