import { LoggerInterface, LogLevel } from './types';

export class Logger implements LoggerInterface {
  private level: LogLevel;

  constructor(level: LogLevel = LogLevel.INFO) {
    this.level = level;
  }

  debug(message: string, meta?: Record<string, any>): void {
    if (this.level >= LogLevel.DEBUG) {
      this.log('debug', message, meta);
    }
  }

  info(message: string, meta?: Record<string, any>): void {
    if (this.level >= LogLevel.INFO) {
      this.log('info', message, meta);
    }
  }

  warn(message: string, meta?: Record<string, any>): void {
    if (this.level >= LogLevel.WARN) {
      this.log('warn', message, meta);
    }
  }

  error(message: string, meta?: Record<string, any>): void {
    if (this.level >= LogLevel.ERROR) {
      this.log('error', message, meta);
    }
  }

  private log(level: string, message: string, meta?: Record<string, any>): void {
    const timestamp = new Date().toISOString();
    const metaString = meta ? ` ${JSON.stringify(meta)}` : '';

    switch (level) {
      case 'debug':
        console.debug(`[${timestamp}] [DEBUG] ${message}${metaString}`);
        break;
      case 'info':
        console.info(`[${timestamp}] [INFO] ${message}${metaString}`);
        break;
      case 'warn':
        console.warn(`[${timestamp}] [WARN] ${message}${metaString}`);
        break;
      case 'error':
        console.error(`[${timestamp}] [ERROR] ${message}${metaString}`);
        break;
    }
  }
}

export const defaultLogger = new Logger(
  process.env.NODE_ENV === 'production' ? LogLevel.INFO : LogLevel.DEBUG
);
