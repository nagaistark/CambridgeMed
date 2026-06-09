import { myEnv } from 'validateConfig.ts';
import logger from 'logger.ts';
import { MongoClient, MongoClientOptions, Db } from 'mongodb';
import { Server } from 'node:http';

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
         stack: input.stack ? sanitizeString(input.stack) : undefined,
      };
   }

   /* TS 4.9+: `'message' in input` narrows to `{ message: unknown }`, making the `as` assertion unnecessary. */
   if (input !== null && typeof input === 'object' && 'message' in input) {
      if (typeof input.message === 'string') {
         return { message: sanitizeString(input.message) };
      }
   }

   return { message: 'Unknown Error' };
}

export class DatabaseService {
   #client: MongoClient | null = null;
   #isConnected: boolean = false;
   #isShuttingDownIntentionally: boolean = false;
   readonly #uri: string;
   readonly #name: string;

   readonly #maxRetries: number = myEnv.database.maxRetries;
   readonly #baseDelay: number = myEnv.database.baseDelay;
   readonly #gracePeriodMS: number = myEnv.database.gracePeriodMS;

   #watchdogTimer: NodeJS.Timeout | null = null;
   #abortController: AbortController = new AbortController();

   /* Differentiates "we lost a previously healthy connection" from "we never connected". */
   #hasEverConnected: boolean = false;

   constructor(uri: string, name: string) {
      this.#uri = uri;
      this.#name = name;
   }

   public async connect(): Promise<MongoClient> {
      let attempt = 0;

      while (attempt < this.#maxRetries) {
         /* ZOMBIE CHECK 1: Before making any attempt, check if we're shutting down. */
         if (this.#isShuttingDownIntentionally) {
            logger.info(
               `[${this.#name}] Connection aborted intentionally prior to attempt.`
            );
            throw new Error(`Aborted connection to ${this.#name}.`);
         }

         logger.info(
            `[${this.#name}] Connection attempt ${attempt + 1}/${this.#maxRetries}...`
         );

         /* Early return if the client already exists and is healthy. */
         if (this.#client !== null && this.#isConnected) {
            return this.#client;
         }

         try {
            /* Proactive cleanup of any stale client before creating a new one. */
            if (this.#client !== null) {
               try {
                  await this.#client.close();
               } catch {
                  logger.warn(
                     `[${this.#name}] Minor: Could not close stale client.`
                  );
               }
               this.#client = null;
               this.#isConnected = false;
            }

            const options: MongoClientOptions = {
               maxPoolSize: myEnv.database.maxPoolSize,
               serverSelectionTimeoutMS:
                  myEnv.database.serverSelectionTimeoutMS,
               socketTimeoutMS: myEnv.database.socketTimeoutMS,
               heartbeatFrequencyMS: myEnv.database.heartbeatFrequencyMS,
            };

            this.#client = new MongoClient(this.#uri, options);
            this.#attachListeners(this.#client);

            /* This can hang for up to `serverSelectionTimeoutMS` milliseconds. */
            await this.#client.connect();

            /* ZOMBIE CHECK 2: We may have connected, but did the app trigger cleanup while we were waiting? */
            if (this.#isShuttingDownIntentionally) {
               logger.warn(
                  `[${this.#name}] Connected, but shutting down. Immediately closing.`
               );
               try {
                  await this.#client.close();
               } catch {
                  logger.warn(
                     `[${this.#name}] Could not close connection during shutdown.`
                  );
               }
               throw new Error(
                  `Aborted connection to ${this.#name} immediately after connecting.`
               );
            }

            this.#isConnected = true;
            this.#hasEverConnected = true;
            logger.info(`[${this.#name}] Connected.`);

            return this.#client;
         } catch (error) {
            /* ZOMBIE CHECK 3: We failed, but if we're shutting down, don't bother retrying. */
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

            /* Interruptible delay. If #abortController.abort() is called, this wakes up instantly. */
            await this.#delay(delayMs);
         }
      }

      /* We should never reach this line. */
      throw new Error(`Unexpected exit from connect loop for ${this.#name}`);
   }

   #delay(ms: number): Promise<void> {
      return new Promise(resolve => {
         const timeout = setTimeout(resolve, ms);

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

   #attachListeners(client: MongoClient): void {
      client.on('topologyDescriptionChanged', event => {
         if (this.#isShuttingDownIntentionally) return;

         const allServersUnknown = [
            ...event.newDescription.servers.values(),
         ].every(s => s.type === 'Unknown');

         const anyServerKnown = [
            ...event.previousDescription.servers.values(),
         ].some(s => s.type !== 'Unknown');

         if (allServersUnknown && anyServerKnown && this.#hasEverConnected) {
            this.#isConnected = false;
            logger.warn(
               `[${this.#name}] All servers unreachable. Starting ${this.#gracePeriodMS / 1000}s watchdog...`
            );
            this.#startWatchdog();
         } else if (!allServersUnknown && this.#watchdogTimer !== null) {
            logger.info(
               `[${this.#name}] Server(s) reachable again. Reconnected.`
            );
            this.#isConnected = true;
            this.#stopWatchdog();
         }
      });

      client.on('error', err => {
         if (this.#isShuttingDownIntentionally) return;
         logger.error(
            `[${this.#name}] Runtime Error: ${sanitizeError(err).message}`
         );
      });
   }

   #startWatchdog(): void {
      if (this.#watchdogTimer) return;

      this.#watchdogTimer = setTimeout(() => {
         this.#watchdogTimer = null;
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

   public get isConnected(): boolean {
      return this.#isConnected;
   }

   /* The raw MongoClient. Prefer `db()` for collection access. */
   public get client(): MongoClient | null {
      return this.#client;
   }

   /* Returns a `Db` instance for this service. @param dbName - Defaults to the database name embedded in the URI (e.g. the "mydb" in `mongodb://host:27017/mydb`). The URIs must include a database name. */
   public db(dbName?: string): Db {
      if (this.#client === null) {
         throw new Error(
            `[${this.#name}] Not connected. Call connect() first.`
         );
      }
      return this.#client.db(dbName);
   }

   public async shutdown(): Promise<void> {
      this.#isShuttingDownIntentionally = true;
      this.#abortController.abort(); // Instantly kill any pending backoff delay.
      this.#isConnected = false;
      this.#stopWatchdog('shutdown');
      if (this.#client === null) return;
      await this.#client.close();
      this.#client = null;
   }
}

export class DatabaseManager {
   /* Static hard-private instance for the Singleton. */
   static #instance: DatabaseManager | null = null;

   #auth: DatabaseService;
   #clinic: DatabaseService;
   #audit: DatabaseService;

   #isInitialized: boolean = false;
   #isCleanedUp: boolean = false;
   #initializingPromise: Promise<void> | null = null;

   private constructor() {
      this.#auth = new DatabaseService(myEnv.database.authUri, 'AuthDB');
      this.#clinic = new DatabaseService(myEnv.database.appUri, 'ClinicDB');
      this.#audit = new DatabaseService(myEnv.database.auditUri, 'AuditDB');
   }

   public static getInstance(): DatabaseManager {
      if (!this.#instance) {
         this.#instance = new DatabaseManager();
      }
      return this.#instance;
   }

   public initialize(): Promise<void> {
      /* Reset so cleanup() works correctly if this instance is ever reused. Must come before anything else. */
      this.#isCleanedUp = false;

      if (this.#isInitialized) {
         logger.info('DatabaseManager already initialized. Skipping...');
         return Promise.resolve();
      }

      /* Concurrent callers join the existing wait instead of racing ahead. */
      if (this.#initializingPromise) {
         logger.warn(
            'Database initialization already in progress. Joining the existing wait...'
         );
         return this.#initializingPromise;
      }

      this.#initializingPromise = (async () => {
         try {
            logger.info(`Initializing all database connections...`);

            /* If any service fails, Promise.all rejects immediately. */
            await Promise.all([
               this.#auth.connect(),
               this.#clinic.connect(),
               this.#audit.connect(),
            ]);

            this.#isInitialized = true;
            logger.info(`All databases are connected and ready`);
         } catch (error) {
            logger.error(`Database initialization failed. Shutting down..`);
            await this.cleanup();
            throw new Error(
               `Initialization failed: ${sanitizeError(error).message}`
            );
         } finally {
            /* Always clear the lock. On success, #isInitialized guards future calls. On failure, clearing this allows a retry if desired. */
            this.#initializingPromise = null;
         }
      })();

      return this.#initializingPromise;
   }

   public get auth(): DatabaseService {
      return this.#auth;
   }
   public get clinic(): DatabaseService {
      return this.#clinic;
   }
   public get audit(): DatabaseService {
      return this.#audit;
   }

   public async cleanup(): Promise<void> {
      if (this.#isCleanedUp) {
         logger.info(`DatabaseManager: cleanup already completed, skipping...`);
         return;
      }

      logger.info(`Cleaning up database connections..`);

      this.#isCleanedUp = true;
      this.#isInitialized = false;

      const results = await Promise.allSettled([
         this.#auth.shutdown(),
         this.#clinic.shutdown(),
         this.#audit.shutdown(),
      ]);

      const dbNames = ['AuthDB', 'ClinicDB', 'AuditDB'] as const;

      results.forEach((result, index) => {
         if (result.status === 'rejected') {
            logger.error(
               `[${dbNames[index]}] Failed to shut down cleanly: ${sanitizeError(result.reason).message}`
            );
         }
      });
   }
}

/* Graceful shutdown
   Module-level sentinel prevents duplicate handling. */
let isShutdownCalled = false;

/*
   Used in server.ts via:
   process.once('SIGINT',  () => handleGracefulShutdown(server, 'SIGINT'));
   process.once('SIGTERM', () => handleGracefulShutdown(server, 'SIGTERM'));
*/
export const handleGracefulShutdown = async (
   server: Server,
   signal: 'SIGINT' | 'SIGTERM'
) => {
   if (isShutdownCalled) {
      logger.warn(`Shutdown already in progress. Ignoring duplicate signal.`);
      return;
   }
   isShutdownCalled = true;

   logger.info(`[${signal}] Initiating graceful exit...`);

   /* Force-kill if graceful logic hangs. */
   const forceQuit = setTimeout(() => {
      logger.error(`Shutdown timed out. Forcing exit...`);
      server.closeAllConnections();
      process.exit(1);
   }, 10000).unref();

   let hasErrorDuringShutdown = false;

   try {
      /* Step 1: Close the HTTP server first. We deliberately don't re-throw here so that a server error doesn't skip database cleanup. */
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

      /* Step 2: Close database connections. */
      const dbManager = DatabaseManager.getInstance();
      await dbManager.cleanup();
      logger.info(`Database connections closed.`);

      clearTimeout(forceQuit);
      logger.info(`Graceful shutdown complete.`);

      process.exit(hasErrorDuringShutdown ? 1 : 0);
   } catch (error) {
      /* Outer catch only triggers if database cleanup itself throws. */
      logger.error(`Error during shutdown: ${sanitizeError(error).message}`);
      process.exit(1);
   }
};
