import winston from 'winston';
import util from 'util';

// 1. Create a barebones Winston logger.
// We strip out splat() and all the other metadata formatters because we don't need them anymore.
const winstonLogger = winston.createLogger({
   level: process.env.NODE_ENV === 'production' ? 'http' : 'debug',
   format: winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.colorize(),
      winston.format.printf(({ level, message, timestamp }) => {
         // Winston now only receives a single, perfectly formatted string.
         return `${timestamp} [${level}]: ${message}`;
      })
   ),
   transports: [new winston.transports.Console()],
});

// 2. Create a factory function that intercepts your variadic arguments.
const createLogMethod = (level: string) => {
   return (...args: any[]) => {
      // util.formatWithOptions is the exact engine behind console.log.
      // It handles multiple args, deep nesting, arrays, and string interpolation natively.
      const formattedMessage = util.formatWithOptions(
         { colors: true, depth: null },
         ...args
      );

      // Pass the perfectly formatted string to Winston
      winstonLogger.log(level, formattedMessage);
   };
};

// 3. Export your clean, strongly-typed logger API
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
