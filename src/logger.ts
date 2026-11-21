import winston from 'winston';
import util from 'node:util';
import { myEnv } from './validateConfig.ts';

const isProduction = myEnv.environment === 'production';
const isInteractiveTerminal =
   process.stdout.isTTY && process.env.NO_COLOR === undefined;

/* Keep newline-delimited JSON when stdout is redirected, so `pnpm dev > app.log`
   remains machine-readable.  A terminal gets the compact presentation instead. */
const format = !isInteractiveTerminal
   ? winston.format.combine(winston.format.timestamp(), winston.format.json())
   : winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.colorize(),
        winston.format.printf(
           ({ level, message, timestamp }) =>
              `${String(timestamp)} ${String(level).padEnd(7)} ${String(message)}`
        )
     );

const winstonLogger = winston.createLogger({
   level: isProduction ? 'http' : 'debug',
   format,
   transports: [new winston.transports.Console()],
});

type LogLevel =
   'error' | 'warn' | 'info' | 'http' | 'verbose' | 'debug' | 'silly';

type LogMethod = (...args: readonly unknown[]) => void;

/* util.formatWithOptions is the engine behind console.log. Colours are for terminals only; the depth cap keeps a stray whole-document log from dumping nested (possibly PHI) data. */
const createLogMethod =
   (level: LogLevel): LogMethod =>
   (...args) => {
      winstonLogger.log(
         level,
         util.formatWithOptions(
            { colors: isInteractiveTerminal, depth: 4 },
            ...args
         )
      );
   };

const logger = {
   error: createLogMethod('error'),
   warn: createLogMethod('warn'),
   info: createLogMethod('info'),
   http: createLogMethod('http'),
   verbose: createLogMethod('verbose'),
   debug: createLogMethod('debug'),
   silly: createLogMethod('silly'),
};

export default logger;
