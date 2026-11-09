import winston from 'winston';
import util from 'node:util';
import { myEnv } from './validateConfig.ts';

const isProduction = myEnv.environment === 'production';

/* Production: one JSON object per line with an ISO-8601 UTC timestamp, which log aggregators parse natively. Development: colourised and human-readable. */
const format = isProduction
   ? winston.format.combine(winston.format.timestamp(), winston.format.json())
   : winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.colorize(),
        winston.format.printf(
           ({ level, message, timestamp }) =>
              `${String(timestamp)} [${level}]: ${String(message)}`
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
         util.formatWithOptions({ colors: !isProduction, depth: 4 }, ...args)
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
