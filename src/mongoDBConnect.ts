import { myEnv } from './validateConfig.ts';
import logger from './logger.ts';
import {
   Db,
   MongoClient,
   MongoParseError,
   MongoServerError,
   type MongoClientOptions,
} from 'mongodb';
import { Redacted } from 'effect';
import { sanitizeError } from '@utils/sanitizeError.ts';

const MAX_BACKOFF_MS = 30_000 as const;
const APP_NAME = 'cambridgemed-api' as const;

/* Server-side "your credentials are wrong" codes. 18 = AuthenticationFailed; 8000 = Atlas's "bad auth". Retrying cannot fix either. */
const AUTH_FAILED_CODE = 18 as const;
const ATLAS_BAD_AUTH_CODE = 8000 as const;

/* MongoParseError = an option the driver rejects. Network and server-selection errors are deliberately NOT here: those can heal on their own. */
function isNonRetryableConnectError(err: unknown): boolean {
   if (err instanceof MongoParseError) return true;
   return (
      err instanceof MongoServerError &&
      (err.code === AUTH_FAILED_CODE || err.code === ATLAS_BAD_AUTH_CODE)
   );
}

export class DatabaseService {
   #client: MongoClient | null = null;
   #isConnected: boolean = false;
   #isShuttingDownIntentionally: boolean = false;
   readonly #uri: Redacted.Redacted<string>;
   readonly #name: string;

   readonly #maxRetries: number = myEnv.database.maxRetries;
   readonly #baseDelay: number = myEnv.database.baseDelay;
   readonly #gracePeriodMS: number = myEnv.database.gracePeriodMS;

   #watchdogTimer: NodeJS.Timeout | null = null;
   #abortController: AbortController = new AbortController();

   /* Differentiates "we lost a previously healthy connection" from "we never connected". */
   #hasEverConnected: boolean = false;

   constructor(uri: Redacted.Redacted<string>, name: string) {
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
               connectTimeoutMS: myEnv.database.serverSelectionTimeoutMS,
               socketTimeoutMS: myEnv.database.socketTimeoutMS,
               heartbeatFrequencyMS: myEnv.database.heartbeatFrequencyMS,
               waitQueueTimeoutMS: myEnv.database.waitQueueTimeoutMS,
               retryWrites: true,
               writeConcern: { w: 'majority' },
               appName: APP_NAME,
               serverApi: { version: '1', deprecationErrors: true },
            };

            this.#client = new MongoClient(Redacted.value(this.#uri), options);
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

            /* No amount of waiting fixes a rejected credential or an invalid option: fail now, with the real reason, instead of burning the whole backoff schedule. The half-open client is closed by DatabaseManager.initialize's catch -> cleanup() -> shutdown(). */
            if (isNonRetryableConnectError(error)) {
               logger.error(
                  `[${this.#name}] Non-retryable connection error: ${sanitizeError(error).message}`
               );
               throw new Error(
                  `Failed to connect to ${this.#name}: the configuration was rejected (not retrying).`
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

            /* "Equal jitter": half deterministic, half random, capped. */
            const ceilingMs = Math.min(
               this.#baseDelay * 2 ** attempt,
               MAX_BACKOFF_MS
            );
            const delayMs = Math.round(
               ceilingMs / 2 + Math.random() * (ceilingMs / 2)
            );

            logger.warn(
               `[${this.#name}] Connection failed: ${sanitizeError(error).message}. Retrying in ${delayMs / 1000}s... (Attempt ${attempt}/${this.#maxRetries})`
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
         const abortHandler = () => {
            clearTimeout(timeout);
            resolve();
         };

         const timeout = setTimeout(() => {
            /* If the timer finishes naturally, clean up the unused listener */
            this.#abortController.signal.removeEventListener(
               'abort',
               abortHandler
            );
            resolve();
         }, ms);

         /* Listen for early cancellation */
         this.#abortController.signal.addEventListener('abort', abortHandler, {
            once: true,
         });
      });
   }

   #attachListeners(client: MongoClient): void {
      client.on('topologyDescriptionChanged', event => {
         if (this.#isShuttingDownIntentionally || !this.#hasEverConnected)
            return;

         const { type } = event.newDescription;
         const isDegraded =
            type === 'Unknown' || type === 'ReplicaSetNoPrimary';

         if (isDegraded && this.#watchdogTimer === null) {
            this.#isConnected = false;
            logger.warn(
               `[${this.#name}] No usable primary. Starting ${this.#gracePeriodMS / 1000}s watchdog...`
            );
            this.#startWatchdog();
         } else if (!isDegraded && this.#watchdogTimer !== null) {
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
         process.exitCode = 1;
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
      if (this.#isCleanedUp) {
         return Promise.reject(
            new Error(
               `DatabaseManager is single-use: it was already cleaned up.`
            )
         );
      }

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
            /* Always clear the lock. On success, #isInitialized guards future calls. On failure the manager has cleaned itself up and cannot be re-initialized. */
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
