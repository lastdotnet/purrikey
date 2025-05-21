import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { TransactionRequest, TransactionResponse } from '@ethersproject/abstract-provider';
import { Deferrable, defineReadOnly } from '@ethersproject/properties';
import { ethers, providers, Signer } from 'ethers';
import { defaultLogger } from '../utils/logging';
import { derToSignature } from '../utils/signature';

export class DirectKmsTransactionSigner extends Signer {
  private kmsClient: KMSClient;
  private _address: string | null = null;
  private debug: boolean;
  private kmsKeyId: string;
  private region: string;
  private _cachedPublicKeys: Map<string, string> = new Map();
  private maxRetries: number;
  private retryDelay: number;

  constructor(
    keyId: string,
    provider?: providers.Provider,
    region?: string,
    debug = false,
    maxRetries = 3,
    retryDelay = 500
  ) {
    super();
    this.kmsKeyId = keyId;
    this.region = region || process.env.REGION || 'us-west-2';
    this.debug = debug;
    this.maxRetries = maxRetries;
    this.retryDelay = retryDelay;

    if (provider) {
      defineReadOnly(this, 'provider', provider);
    }

    if (this.debug) {
      defaultLogger.debug('KMS Debug - Creating KMS signer', {
        keyId,
        region: this.region,
        environment: process.env.NODE_ENV,
        lambdaContext: !!process.env.AWS_LAMBDA_FUNCTION_NAME,
      });
    }

    this.kmsClient = new KMSClient({
      region: this.region,
      customUserAgent: 'KmsEthereumSigner/1.0',
    });
  }

  private parseDERPublicKey(derPublicKey: Buffer): Buffer {
    try {
      if (this.debug) {
        defaultLogger.debug('KMS Debug - Parsing DER public key', {
          derLength: derPublicKey.length,
          derHexStart: derPublicKey.slice(0, 10).toString('hex'),
        });
      }

      let pos = 0;

      if (derPublicKey[pos++] !== 0x30) {
        throw new Error('Invalid DER format: Expected sequence tag 0x30');
      }

      const lengthByte = derPublicKey[pos++];
      if (lengthByte >= 0x80) {
        const numLengthBytes = lengthByte & 0x7f;
        pos += numLengthBytes;
      }

      if (derPublicKey[pos++] !== 0x30) {
        throw new Error('Invalid DER format: Expected AlgorithmIdentifier sequence');
      }

      const algIdLength = derPublicKey[pos++];
      pos += algIdLength;

      if (derPublicKey[pos++] !== 0x03) {
        throw new Error('Invalid DER format: Expected BitString tag 0x03');
      }

      pos++;
      pos++;

      const keyBytes = derPublicKey.slice(pos);

      if (keyBytes[0] !== 0x04) {
        throw new Error(
          `Expected uncompressed public key starting with 0x04, got 0x${keyBytes[0].toString(16)}`
        );
      }

      if (this.debug) {
        defaultLogger.debug('KMS Debug - Extracted uncompressed public key', {
          keyLength: keyBytes.length,
          keyHexStart: keyBytes.slice(0, 10).toString('hex'),
        });
      }

      return keyBytes;
    } catch (err) {
      defaultLogger.error('KMS Debug - Failed to parse DER public key', {
        error: err instanceof Error ? err.message : String(err),
        derLength: derPublicKey.length,
        derHexStart: derPublicKey.slice(0, 10).toString('hex'),
      });

      return derPublicKey;
    }
  }

  async getAddress(): Promise<string> {
    if (this._address) return this._address;
    if (this._cachedPublicKeys.has(this.kmsKeyId)) {
      const cachedAddress = this._cachedPublicKeys.get(this.kmsKeyId);
      if (cachedAddress) {
        this._address = cachedAddress;
        return this._address;
      }
    }

    try {
      if (this.debug) {
        defaultLogger.debug('KMS Debug - Getting public key', { keyId: this.kmsKeyId });
      }

      const publicKeyResponse = await this.executeWithRetry('getPublicKey', () =>
        this.kmsClient.send(
          new GetPublicKeyCommand({
            KeyId: this.kmsKeyId,
          })
        )
      );

      if (!publicKeyResponse.PublicKey) {
        throw new Error('Public key not found in KMS response');
      }

      const derPublicKey = Buffer.from(publicKeyResponse.PublicKey);
      const uncompressedPublicKey = this.parseDERPublicKey(derPublicKey);

      try {
        const ethAddress = ethers.utils.computeAddress(uncompressedPublicKey);

        this._address = ethAddress;
        this._cachedPublicKeys.set(this.kmsKeyId, ethAddress);

        if (this.debug) {
          defaultLogger.debug('KMS Debug - Generated Ethereum address', {
            address: ethAddress,
            publicKeyLength: uncompressedPublicKey.length,
            publicKeyHexStart: uncompressedPublicKey.slice(0, 10).toString('hex'),
          });
        }

        return ethAddress;
      } catch (e) {
        defaultLogger.warn(
          'KMS Debug - First attempt to compute address failed, trying with modified key',
          {
            error: e instanceof Error ? e.message : String(e),
          }
        );

        if (uncompressedPublicKey.length > 65) {
          const strippedKey = Buffer.concat([
            Buffer.from([0x04]),
            uncompressedPublicKey.slice(-64),
          ]);

          if (this.debug) {
            defaultLogger.debug('KMS Debug - Trying stripped key format', {
              strippedKeyLength: strippedKey.length,
              strippedKeyHexStart: strippedKey.slice(0, 10).toString('hex'),
            });
          }

          const ethAddress = ethers.utils.computeAddress(strippedKey);
          this._address = ethAddress;
          this._cachedPublicKeys.set(this.kmsKeyId, ethAddress);

          return ethAddress;
        }

        throw e;
      }
    } catch (error) {
      defaultLogger.error('KMS Error - Failed to get address:', {
        error: error instanceof Error ? error.message : String(error),
        code: (error as any)?.code,
        type: error?.constructor?.name,
        requestId: (error as any)?.$metadata?.requestId,
        keyId: this.kmsKeyId,
      });
      throw new Error(
        `Error getting address from KMS: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async signMessage(message: ethers.utils.Bytes | string): Promise<string> {
    try {
      const msgToSign = typeof message === 'string' ? message : ethers.utils.arrayify(message);
      const messageHash = ethers.utils.hashMessage(msgToSign);

      if (this.debug) {
        defaultLogger.debug('KMS Debug - Signing message', {
          messageHashHex: messageHash,
        });
      }

      const signCommand = new SignCommand({
        KeyId: this.kmsKeyId,
        Message: Buffer.from(ethers.utils.arrayify(messageHash).buffer),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await this.executeWithRetry('signMessage', () =>
        this.kmsClient.send(signCommand)
      );

      if (!response.Signature) {
        throw new Error('No signature returned from KMS');
      }

      const address = await this.getAddress();

      const normalizedSig = await derToSignature(
        Buffer.from(response.Signature || new Uint8Array()),
        messageHash,
        0,
        address
      );

      if (this.debug) {
        defaultLogger.debug('KMS Debug - Signature normalized for message signing', {
          r: normalizedSig.r.substring(0, 10) + '...',
          s: normalizedSig.s.substring(0, 10) + '...',
          v: normalizedSig.v,
          recoveryParam: normalizedSig.recoveryParam,
        });
      }

      return ethers.utils.joinSignature(normalizedSig);
    } catch (error) {
      defaultLogger.error('KMS Error - Failed to sign message:', {
        error: error instanceof Error ? error.message : String(error),
        code: (error as any)?.code,
        type: error?.constructor?.name,
        requestId: (error as any)?.$metadata?.requestId,
        keyId: this.kmsKeyId,
      });
      throw new Error(
        `Error signing message with KMS: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async signTransaction(transaction: Deferrable<TransactionRequest>): Promise<string> {
    try {
      const tx = await ethers.utils.resolveProperties(transaction);

      if (this.debug) {
        defaultLogger.debug('KMS Debug - Signing transaction', {
          to: tx.to,
          chainId: tx.chainId,
          gasLimit: tx.gasLimit?.toString(),
          type: tx.type || 2,
        });
      }

      if (!tx.chainId && this.provider) {
        const network = await this.provider.getNetwork();
        tx.chainId = network.chainId;
      }

      if (!tx.chainId) {
        throw new Error('Transaction missing chainId and no provider available');
      }

      tx.type = 2;

      if ('gasPrice' in tx) {
        delete tx.gasPrice;
      }

      if ((!tx.maxFeePerGas || !tx.maxPriorityFeePerGas) && this.provider) {
        const feeData = await this.provider.getFeeData();
        tx.maxFeePerGas =
          tx.maxFeePerGas ||
          feeData.maxFeePerGas ||
          feeData.lastBaseFeePerGas?.mul(2) ||
          ethers.BigNumber.from(100000000);
        tx.maxPriorityFeePerGas =
          tx.maxPriorityFeePerGas || feeData.maxPriorityFeePerGas || ethers.BigNumber.from(0);
      }

      const unsignedTx = ethers.utils.serializeTransaction(tx as ethers.UnsignedTransaction);
      const messageHash = ethers.utils.keccak256(unsignedTx);

      const signCommand = new SignCommand({
        KeyId: this.kmsKeyId,
        Message: Buffer.from(ethers.utils.arrayify(messageHash).buffer),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await this.executeWithRetry('signTransaction', () =>
        this.kmsClient.send(signCommand)
      );

      if (!response.Signature) {
        throw new Error('No signature returned from KMS');
      }

      const address = await this.getAddress();

      const normalizedSig = await derToSignature(
        Buffer.from(response.Signature || new Uint8Array()),
        messageHash,
        Number(tx.chainId),
        address
      );

      if (this.debug) {
        defaultLogger.debug('KMS Debug - Signature normalized for transaction signing', {
          r: normalizedSig.r.substring(0, 10) + '...',
          s: normalizedSig.s.substring(0, 10) + '...',
          v: normalizedSig.v,
          recoveryParam: normalizedSig.recoveryParam,
          chainId: tx.chainId,
        });
      }

      return ethers.utils.serializeTransaction(tx as ethers.UnsignedTransaction, normalizedSig);
    } catch (error) {
      defaultLogger.error('KMS Error - Failed to sign transaction:', {
        error: error instanceof Error ? error.message : String(error),
        code: (error as any)?.code,
        type: error?.constructor?.name,
        requestId: (error as any)?.$metadata?.requestId,
        keyId: this.kmsKeyId,
        chainId: transaction.chainId,
      });
      throw new Error(
        `Error signing transaction with KMS: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  connect(provider: providers.Provider): DirectKmsTransactionSigner {
    return new DirectKmsTransactionSigner(this.kmsKeyId, provider, this.region, this.debug);
  }

  async sendTransaction(transaction: Deferrable<TransactionRequest>): Promise<TransactionResponse> {
    if (!this.provider) {
      throw new Error('Provider required for sendTransaction');
    }

    try {
      const tx = await ethers.utils.resolveProperties(transaction);

      tx.type = 2;

      if ('gasPrice' in tx) {
        delete tx.gasPrice;
      }

      const populated = await this.populateTransaction(tx);

      defaultLogger.debug('KMS Debug - About to sign transaction:', {
        to: populated.to,
        chainId: populated.chainId,
        type: populated.type,
        maxFeePerGas: populated.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: populated.maxPriorityFeePerGas?.toString(),
      });

      const signedTx = await this.signTransaction(populated);
      defaultLogger.debug('KMS Debug - Transaction signed successfully');

      return await this.provider.sendTransaction(signedTx);
    } catch (error) {
      defaultLogger.error('KMS Error - Failed to send transaction:', {
        error: error instanceof Error ? error.message : String(error),
        code: (error as any)?.code,
        type: error?.constructor?.name,
        requestId: (error as any)?.$metadata?.requestId,
      });
      throw error;
    }
  }

  async populateTransaction(
    transaction: Deferrable<TransactionRequest>
  ): Promise<TransactionRequest> {
    const tx = await ethers.utils.resolveProperties(transaction);
    const populated: TransactionRequest = { ...tx };

    populated.type = 2;

    if ('gasPrice' in populated) {
      delete populated.gasPrice;
    }

    if (populated.to != null) {
      try {
        populated.to = await this.resolveName(populated.to);
      } catch (error) {
        if (process.env.NODE_ENV === 'test') {
          defaultLogger.debug('Test environment detected, skipping name resolution');
        } else {
          throw error;
        }
      }
    }

    if (populated.nonce == null) {
      populated.nonce = await this.getTransactionCount('pending');
    }

    if (populated.gasLimit == null) {
      populated.gasLimit = await this.estimateGas(populated).catch((error) => {
        return Promise.reject(error);
      });
    }

    if (populated.chainId == null) {
      populated.chainId = await this.getChainId();
    }

    if ((!populated.maxFeePerGas || !populated.maxPriorityFeePerGas) && this.provider) {
      const feeData = await this.provider.getFeeData();
      populated.maxFeePerGas =
        populated.maxFeePerGas ||
        feeData.maxFeePerGas ||
        feeData.lastBaseFeePerGas?.mul(2) ||
        ethers.BigNumber.from(100000000);
      populated.maxPriorityFeePerGas =
        populated.maxPriorityFeePerGas || feeData.maxPriorityFeePerGas || ethers.BigNumber.from(0);
    }

    return populated;
  }

  private async executeWithRetry<T>(
    operation: string,
    fn: () => Promise<T>,
    maxRetries = this.maxRetries,
    retryDelay = this.retryDelay
  ): Promise<T> {
    let attempts = 0;
    const isRetrying = true;

    while (isRetrying) {
      try {
        attempts++;
        return await fn();
      } catch (error: unknown) {
        if (attempts >= maxRetries) {
          this.trackAwsError(operation, error);
          throw error;
        }

        const errorObj = error as Record<string, any>;

        const isRetryable =
          error &&
          typeof error === 'object' &&
          (errorObj.name === 'RetryableError' ||
            errorObj.name === 'UnrecognizedClientException' ||
            errorObj.code === 'ServiceUnavailable' ||
            errorObj.code === 'ThrottlingException' ||
            (errorObj.$metadata &&
              typeof errorObj.$metadata === 'object' &&
              'httpStatusCode' in errorObj.$metadata &&
              typeof errorObj.$metadata.httpStatusCode === 'number' &&
              errorObj.$metadata.httpStatusCode >= 500));

        if (!isRetryable) {
          this.trackAwsError(operation, error);
          throw error;
        }

        defaultLogger.warn(
          `KMS operation ${operation} failed, retrying (${attempts}/${maxRetries})`,
          {
            error: error instanceof Error ? error.message : String(error),
            errorCode: typeof errorObj.code === 'string' ? errorObj.code : 'unknown',
            errorName:
              typeof errorObj.name === 'string'
                ? errorObj.name
                : (error && error.constructor && error.constructor.name) || 'unknown',
            attempt: attempts,
          }
        );

        const delay = retryDelay * Math.pow(2, attempts - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw new Error(`Unexpected exit from retry loop in ${operation}`);
  }

  private trackAwsError(operation: string, error: any): void {
    try {
      defaultLogger.error(`KMS Error during ${operation}`, {
        errorName:
          error && typeof error === 'object' && 'name' in error ? error.name : 'UnknownError',
        errorCode:
          error && typeof error === 'object' && 'code' in error ? error.code : 'UnknownCode',
        statusCode: error?.$metadata?.httpStatusCode,
        requestId: error?.$metadata?.requestId,
      });
    } catch (e) {
      defaultLogger.error('Failed to track KMS error', { error: String(e) });
    }
  }

  _checkProvider(operation: string): void {
    if (!this.provider) {
      throw new Error(`${operation} requires a provider`);
    }
  }
}
