import { myEnv } from '@/validateConfig.ts';
import logger from '@/logger.ts';
import mongoose, { Connection, ConnectOptions } from 'mongoose';
import { Server } from 'http';

export function sanitizeError(input: unknown): {
   message: string;
   stack?: string;
} {
   const sanitizeString = (str: string) =>
      str.replace(/\/\/.*:.*@/g, '//****:****@');

   if (typeof input === 'string') {
      return { message: sanitizeString(input) };
   }

   if (input instanceof Error) {
      return {
         message: sanitizeString(input.message || 'Unknown Error'),
         // Sanitize the stack too, as it usually repeats the message at the top!
         stack: input.stack ? sanitizeString(input.stack) : undefined,
      };
   }

   if (input && typeof input === 'object' && 'message' in input) {
      const potentialMessage = (input as Record<string, unknown>).message;
      if (typeof potentialMessage === 'string') {
         return { message: sanitizeString(potentialMessage) };
      }
   }

   return { message: 'Unknown Error' };
}

export class DatabaseService {
   #connection: Connection | null = null;
   #isShuttingDownIntentionally = false;
   #uri: string;
   #name: string;

   // Backoff settings
   #maxRetries = myEnv.database.maxRetries;
   #baseDelay = myEnv.database.baseDelay;

   #watchdogTimer: NodeJS.Timeout | null = null;
   #gracePeriodMS: number = myEnv.database.gracePeriodMS;

   // Abort Controller to instantly cancel pending backoff delay
   #abortController = new AbortController();

   // Flag to differenciate between "we lost a previously healthy connection" and "we never connected in the first place"
   #hasEverConnected: boolean = false;

   constructor(uri: string, name: string) {
      this.#uri = uri;
      this.#name = name;
   }

   public async connect(): Promise<Connection> {
      let attempt = 0;

      while (attempt < this.#maxRetries) {
         // ZOMBIE CHECK 1: Before making any attempt, check if we're shutting down
         if (this.#isShuttingDownIntentionally) {
            logger.info(
               `[${this.#name}] Connection aborted intentionally prior to attempt.`
            );
            throw new Error(`Aborted connection to ${this.#name}.`);
         }

         // Log which attempt we're on before making it, so every attempt is visible
         logger.info(
            `[${this.#name}] Connection attempt ${attempt + 1}/${this.#maxRetries}...`
         );

         if (this.#connection?.readyState === 1) {
            return this.#connection;
         }
         if (this.#connection?.readyState === 2) {
            return this.#connection.asPromise();
         }

         try {
            // Proactive cleanup
            if (this.#connection) {
               try {
                  await this.#connection.close();
               } catch {
                  logger.warn(
                     `[${this.#name}] Minor: Could not close stale connection.`
                  );
               }
               this.#connection = null;
            }

            const options: ConnectOptions = {
               maxPoolSize: myEnv.database.maxPoolSize,
               serverSelectionTimeoutMS:
                  myEnv.database.serverSelectionTimeoutMS,
               socketTimeoutMS: myEnv.database.socketTimeoutMS,
               autoIndex: myEnv.database.autoIndex,
            };

            this.#connection = mongoose.createConnection(this.#uri, options);
            this.#attachListeners(this.#connection);

            // This can hang for up to `serverSelectionTimeoutMS` seconds
            await this.#connection.asPromise();

            // ZOMBIE CHECK 2: We may have connected, but did the app trigger cleanup while we were waiting?
            if (this.#isShuttingDownIntentionally) {
               logger.warn(
                  `[${this.#name}] Connected, but shutting down. Immediately closing.`
               );
               try {
                  await this.#connection.close();
               } catch {
                  logger.warn(
                     `[${this.#name}] Could not close connection during shutdown.`
                  );
               }
               throw new Error(
                  `Aborted connection to ${this.#name} immediately after connecting.`
               );
            }

            return this.#connection;
         } catch (error) {
            // ZOMBIE CHECK 3: We failed, but if we're shutting down, don't bother retrying
            if (this.#isShuttingDownIntentionally) {
               logger.info(
                  `[${this.#name}] Connection failed, and shutdown in progress. Aborting retries.`
               );
               throw new Error(
                  `Aborted connection to ${this.#name} during retries.`
               );
            }

            attempt++;
            if (attempt >= this.#maxRetries) {
               logger.error(
                  `[${this.#name}] Final connection attempt failed: ${sanitizeError(error).message}`
               );
               throw new Error(
                  `Failed to connect to ${this.#name} after ${this.#maxRetries} attempts.`
               );
            }

            const delayMs = this.#baseDelay * Math.pow(2, attempt);
            logger.warn(
               `[${this.#name}] Connection failed. Retrying in ${delayMs / 1000}s... (Attempt ${attempt}/${this.#maxRetries})`
            );

            // NEW: Interruptible delay. If #abortController.abort() is called, this wakes up instantly.
            await this.#delay(delayMs);
         }
      }

      // I hope we never reach this line of code.
      throw new Error(`Unexpected exit from connect loop for ${this.#name}`);
   }

   // NEW: Helper method for an interruptible delay
   #delay(ms: number): Promise<void> {
      return new Promise(resolve => {
         const timeout = setTimeout(resolve, ms);

         // If shutdown is triggered, clear the timeout and resolve immediately
         this.#abortController.signal.addEventListener(
            'abort',
            () => {
               clearTimeout(timeout);
               resolve();
            },
            { once: true }
         );
      });
   }

   #attachListeners(conn: Connection): void {
      conn.on('connected', () => {
         logger.info(`[${this.#name}] Connected.`);
         this.#hasEverConnected = true; // marking that we've had a healthy connection
         this.#stopWatchdog();
      });
      conn.on('error', err => {
         // Suppress error logging once shutdown is in progress.
         if (this.#isShuttingDownIntentionally) return;
         logger.error(
            `[${this.#name}] Runtime Error: ${sanitizeError(err).message}`
         );
      });
      conn.on('disconnected', () => {
         // Only start the watchdog if we previously had a healthy connection.
         if (!this.#isShuttingDownIntentionally && this.#hasEverConnected) {
            logger.warn(
               `[${this.#name}] Lost connection. Starting ${this.#gracePeriodMS / 1000}s watchdog...`
            );
            this.#startWatchdog();
         }
      });
      conn.on('reconnected', () => {
         logger.info(`[${this.#name}] Reconnected to the database.`);
         this.#stopWatchdog();
      });
   }

   #startWatchdog(): void {
      if (this.#watchdogTimer) return;

      this.#watchdogTimer = setTimeout(() => {
         this.#watchdogTimer = null; // Cleaning up the reference immediately so it doesn't outlive the timer's useful life
         logger.error(
            `[${this.#name}] FATAL: Connection not restored within grace period. Triggering shutdown.`
         );

         process.emit('SIGTERM');
      }, this.#gracePeriodMS);
   }

   #stopWatchdog(reason: 'stabilized' | 'shutdown' = 'stabilized'): void {
      if (this.#watchdogTimer) {
         const message =
            reason === 'stabilized'
               ? 'Watchdog cleared. Connection stabilized.'
               : 'Watchdog defused. Shutdown in progress.';
         logger.info(`[${this.#name}] ${message}`);
         clearTimeout(this.#watchdogTimer);
         this.#watchdogTimer = null;
      }
   }

   public get connection(): Connection | null {
      return this.#connection;
   }

   public async shutdown(): Promise<void> {
      this.#isShuttingDownIntentionally = true;
      this.#abortController.abort(); // NEW: Instantly kill any pending backoff delays

      this.#stopWatchdog('shutdown'); // We're being honest about why
      if (!this.#connection) return;
      await this.#connection.close();
   }
}

export class DatabaseManager {
   // Static Hard-Private instance for the Singleton
   static #instance: DatabaseManager | null = null;

   // Hard-Private services
   #auth: DatabaseService;
   #clinic: DatabaseService;
   #isInitialized: boolean = false;
   #isCleanedUp: boolean = false;
   #initializingPromise: Promise<void> | null = null;

   private constructor() {
      this.#auth = new DatabaseService(myEnv.database.authUri, 'AuthDB');
      this.#clinic = new DatabaseService(myEnv.database.appUri, 'ClinicDB');
   }

   public static getInstance(): DatabaseManager {
      if (!this.#instance) {
         this.#instance = new DatabaseManager();
      }
      return this.#instance;
   }

   public initialize(): Promise<void> {
      // Resetting the cleanup flag so that `cleanup()` works correctly if this DatabaseManager instance is ever reused after a previous cleanup. Must come before anything else so that a cleanup triggered during `this` initialization attempt isn't incorrectly skipped
      this.#isCleanedUp = false;

      // If already initialized, do nothing
      if (this.#isInitialized) {
         logger.info('DatabaseManager already initialized. Skipping...');
         return Promise.resolve();
      }

      // If initialization is in progress, return the pending Promise.
      // Now, concurrent callers will "join" the wait instead of skipping ahead.
      if (this.#initializingPromise) {
         logger.warn(
            'Database initialization already in progress. Joining the existing wait...'
         );
         return this.#initializingPromise;
      }

      this.#initializingPromise = (async () => {
         try {
            logger.info(`Initializing all database connections...`);

            // Parallel initialization. If either fails, Promise.all rejects immediately, and we move to the catch block immediately
            await Promise.all([this.#auth.connect(), this.#clinic.connect()]);

            this.#isInitialized = true;
            logger.info(`All databases are connected and ready`);
         } catch (error) {
            logger.error(`Database initialization failed. Shutting down..`);

            // Cleanup calls shutdown() on both services
            await this.cleanup();
            throw new Error(
               `Initialization failed: ${sanitizeError(error).message}`
            );
         } finally {
            // Always clear the lock when done.
            // If it succeeded, #isInitialized catches future calls.
            // If it failed, clearing this allows the app to try again if desired.
            this.#initializingPromise = null;
         }
      })();

      return this.#initializingPromise;
   }

   // Getters to access the services (Hard Privacy means we must use these)
   public get auth(): DatabaseService {
      return this.#auth;
   }
   public get clinic(): DatabaseService {
      return this.#clinic;
   }

   // Graceful cleanup for all services.
   public async cleanup(): Promise<void> {
      if (this.#isCleanedUp) {
         logger.info(`DatabaseManager: cleanup already completed, skipping...`);
         return;
      }

      logger.info(`Cleaning up database connections..`);

      this.#isCleanedUp = true;

      // Ensuring we can't re-initialize while cleaning up
      this.#isInitialized = false;

      const results = await Promise.allSettled([
         this.#auth.shutdown(),
         this.#clinic.shutdown(),
      ]);

      // Inspecting each outcome — allSettled never rejects, but failures hide here
      results.forEach((result, index) => {
         if (result.status === 'rejected') {
            const name = index === 0 ? 'AuthDB' : 'ClinicDB';
            logger.error(
               `[${name}] Failed to shut down cleanly: ${sanitizeError(result.reason)}`
            );
         }
      });
   }
}

// Graceful Shutdown
// Module-level boolean sentinel
let isShutdownCalled = false;

/*
   imported to server.ts and called via
   process.once('SIGINT', () => handleGracefulShutdown(server, 'SIGINT'));
   process.once('SIGTERM', () => handleGracefulShutdown(server, 'SIGTERM'))`
*/
export const handleGracefulShutdown = async (
   server: Server,
   signal: 'SIGINT' | 'SIGTERM'
) => {
   // Guard to prevent multiple consecutive calls
   if (isShutdownCalled) {
      logger.warn(`Shutdown already in progress. Ignoring duplicate signal.`);
      return;
   }
   isShutdownCalled = true;

   logger.info(`[${signal}] Initiating graceful exit...`);

   // Force kill after delay if logic hangs
   const forceQuit = setTimeout(() => {
      logger.error(`Shutdown timed out. Forcing exit...`);
      server.closeAllConnections(); // Failsafe for stubborn active connections
      process.exit(1);
   }, 10000).unref();

   let hasErrorDuringShutdown: boolean = false;

   try {
      // Step 1. Closing the HTTP server. Potential failure should not skip to Step 2
      try {
         await new Promise<void>((resolve, reject) => {
            server.close(err => (err ? reject(err) : resolve()));
            server.closeIdleConnections();
         });
         logger.info(`HTTP server closed.`);
      } catch (serverError) {
         // Logging but not re-throwing!
         hasErrorDuringShutdown = true;
         logger.error(
            `Error closing HTTP server: ${sanitizeError(serverError)}`
         );
      }

      // Step 2. Close database connections.
      const dbManager = DatabaseManager.getInstance();
      await dbManager.cleanup();
      logger.info(`Database connections closed.`);

      clearTimeout(forceQuit);
      logger.info(`Graceful shutdown complete.`);

      // Exit with 1 if there was a server error, otherwise 0
      process.exit(hasErrorDuringShutdown ? 1 : 0);
   } catch (error) {
      // Outer catch that only triggeres if the database cleanup itself throws
      logger.error(`Error during shutdown: ${sanitizeError(error)}`);
      process.exit(1);
   }
};
