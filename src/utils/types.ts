import { ethers } from 'ethers';

export interface NormalisedSig {
  r: string;
  s: string;
  v: number;
  _vs: string;
  yParityAndS: string;
  compact: string;
  recoveryParam: number;
}

export interface LoggerInterface {
  debug: (message: string, meta?: Record<string, any>) => void;
  info: (message: string, meta?: Record<string, any>) => void;
  warn: (message: string, meta?: Record<string, any>) => void;
  error: (message: string, meta?: Record<string, any>) => void;
}

export enum LogLevel {
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4
}

export interface KmsSignerConfig {
  keyId: string;
  provider?: ethers.providers.Provider;
  region?: string;
  debug?: boolean;
  maxRetries?: number;
  retryDelay?: number;
  customEndpoint?: string;
  logLevel?: LogLevel;
  logger?: LoggerInterface;
}