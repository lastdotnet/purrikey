import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { TransactionRequest, TransactionResponse } from '@ethersproject/abstract-provider';
import { Deferrable, defineReadOnly } from '@ethersproject/properties';
import { ethers, providers, Signer } from 'ethers';
import { defaultLogger } from '../utils/logging';
import { decodeDER, derToSignature } from '../utils/signature';

function arrayifyToBuffer(data: string | ethers.utils.BytesLike): Buffer {
  const bytes = ethers.utils.arrayify(data);
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export class KmsTransactionSigner extends Signer {
  private kmsClient: KMSClient;
  private _address: string | null = null;
  private debug: boolean;
  private kmsKeyId: string;
  private region?: string;
  private _cachedPublicKeys: Map<string, string> = new Map();

  constructor(keyId: string, provider?: providers.Provider, region?: string, debug: boolean = false) {
    super();
    this.kmsKeyId = keyId;
    this.region = region;
    this.debug = debug;

    if (provider) {
      defineReadOnly(this, 'provider', provider);
    }

    if (this.debug) {
      defaultLogger.debug('Creating KMS signer', {
        keyId,
        region: region || process.env.REGION || 'us-west-2',
      });
    }

    try {
      this.kmsClient = new KMSClient({ region: this.region || process.env.REGION || 'us-west-2' });
    } catch (error) {
      defaultLogger.error('Error initializing KMS client:', { error: error instanceof Error ? error.message : String(error) });
      throw new Error(`Failed to initialize KMS client: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getAddress(): Promise<string> {
    if (this._address) return this._address;

    try {
      if (this._cachedPublicKeys.has(this.kmsKeyId)) {
        this._address = this._cachedPublicKeys.get(this.kmsKeyId)!;
        return this._address;
      }

      const messageHex = '000000000000000000000000000000000000000000000000000000000000000000000000';
      const message = Buffer.from(messageHex, 'hex');

      const signCommand = new SignCommand({
        KeyId: this.kmsKeyId,
        Message: message,
        MessageType: 'RAW',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await this.kmsClient.send(signCommand);
      if (!response.Signature) {
        throw new Error('KMS signing produced no signature');
      }

      const { r, s } = decodeDER(response.Signature);
      const signature = { r, s, v: 27, recoveryParam: 0 };

      const messageHash = ethers.utils.keccak256(message);

      let address: string | null = null;
      for (let v = 0; v <= 1; v++) {
        try {
          const sigWithV = { ...signature, v: v + 27 };
          const messageBytes = ethers.utils.arrayify(messageHash);
          const recoveredAddress = ethers.utils.recoverAddress(messageBytes, sigWithV);

          if (recoveredAddress && recoveredAddress.startsWith('0x')) {
            address = recoveredAddress;
            break;
          }
        } catch (e) {}
      }

      if (!address) {
        throw new Error('Failed to recover address from KMS signature');
      }

      this._address = address;
      this._cachedPublicKeys.set(this.kmsKeyId, address);

      if (this.debug) {
        defaultLogger.debug('Retrieved address for KMS key:', { address: this._address });
      }

      return this._address;
    } catch (error) {
      defaultLogger.error('Error getting address from KMS:', { error: error instanceof Error ? error.message : String(error) });
      throw new Error(`Error getting address from KMS: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async signMessage(message: ethers.utils.Bytes | string): Promise<string> {
    try {
      if (this.debug) {
        defaultLogger.debug(`Signing message with KMS key ${this.kmsKeyId}`);
      }

      const msgToSign = typeof message === 'string' ? message : ethers.utils.arrayify(message);

      const messageHash = ethers.utils.hashMessage(msgToSign);

      const signCommand = new SignCommand({
        KeyId: this.kmsKeyId,
        Message: arrayifyToBuffer(messageHash),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await this.kmsClient.send(signCommand);

      if (!response.Signature) {
        throw new Error('KMS signing produced no signature');
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
      defaultLogger.error('Error signing message with KMS:', { error: error instanceof Error ? error.message : String(error) });
      throw new Error(`Error signing message with KMS: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async signTransaction(transaction: Deferrable<TransactionRequest>): Promise<string> {
    try {
      const tx = (await ethers.utils.resolveProperties(transaction)) as any;

      tx.type = 2;

      if ('gasPrice' in tx) {
        delete tx.gasPrice;
      }

      if (this.debug) {
        defaultLogger.debug('Signing transaction with KMS key', {
          keyId: this.kmsKeyId,
          to: tx.to,
          data: tx.data ? `${tx.data.toString().substring(0, 10)}...` : undefined,
          value: tx.value?.toString(),
          chainId: tx.chainId,
          gasLimit: tx.gasLimit?.toString(),
          type: tx.type,
          maxFeePerGas: tx.maxFeePerGas?.toString(),
          maxPriorityFeePerGas: tx.maxPriorityFeePerGas?.toString(),
        });
      }

      if (!tx.chainId && this.provider) {
        const network = await this.provider.getNetwork();
        tx.chainId = network.chainId;

        if (this.debug) {
          defaultLogger.debug('Adding chainId from provider', { chainId: tx.chainId });
        }
      }

      if (!tx.chainId) {
        throw new Error('Transaction missing chainId and no provider available');
      }

      if (!tx.maxFeePerGas || !tx.maxPriorityFeePerGas) {
        const feeData = await this.provider!.getFeeData();
        tx.maxFeePerGas =
          tx.maxFeePerGas ||
          feeData.maxFeePerGas ||
          feeData.lastBaseFeePerGas?.mul(2) ||
          ethers.BigNumber.from(100000000);
        tx.maxPriorityFeePerGas = tx.maxPriorityFeePerGas || feeData.maxPriorityFeePerGas || ethers.BigNumber.from(0);
      }

      const unsignedTx = ethers.utils.serializeTransaction(tx as ethers.UnsignedTransaction);
      const messageHash = ethers.utils.keccak256(unsignedTx);

      const signCommand = new SignCommand({
        KeyId: this.kmsKeyId,
        Message: arrayifyToBuffer(messageHash),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      });

      const response = await this.kmsClient.send(signCommand);

      if (!response.Signature) {
        throw new Error('KMS signing produced no signature');
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
      defaultLogger.error('Error signing transaction with KMS:', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new Error(`Error signing transaction with KMS: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  connect(provider: providers.Provider): KmsTransactionSigner {
    return new KmsTransactionSigner(this.kmsKeyId, provider, this.region, this.debug);
  }

  async sendTransaction(transaction: Deferrable<TransactionRequest>): Promise<TransactionResponse> {
    if (!this.provider) {
      throw new Error('Provider required for sendTransaction');
    }

    const tx = await ethers.utils.resolveProperties(transaction);

    tx.type = 2;

    if ('gasPrice' in tx) {
      delete tx.gasPrice;
    }

    const populated = await this.populateTransaction(tx);

    if (this.debug) {
      defaultLogger.debug('KMS Debug - Sending transaction', {
        to: populated.to,
        chainId: populated.chainId,
        type: populated.type,
        maxFeePerGas: populated.maxFeePerGas?.toString(),
        maxPriorityFeePerGas: populated.maxPriorityFeePerGas?.toString(),
      });
    }

    const signedTx = await this.signTransaction(populated);

    return await this.provider.sendTransaction(signedTx);
  }

  async populateTransaction(transaction: Deferrable<TransactionRequest>): Promise<TransactionRequest> {
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

    if (!populated.maxFeePerGas || !populated.maxPriorityFeePerGas) {
      const feeData = await this.provider!.getFeeData();
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

  _checkProvider(operation: string): void {
    if (!this.provider) {
      throw new Error(`${operation} requires a provider`);
    }
  }
}