# KMS Ethereum Signer

An [ethers.js](https://github.com/ethers-io/ethers.js/) compatible signer that uses AWS KMS for Ethereum transaction signing. This allows for secure key management using AWS Key Management Service while maintaining compatibility with ethers.js for Ethereum interactions.

## Features

- **Drop-in replacement** for ethers.js Signer
- **Security** - Private keys never leave AWS KMS
- **Ethereum transaction compatibility** - Type 2 (EIP-1559) transaction support
- **DER signature conversion** - Automatically converts AWS KMS DER signatures to Ethereum format
- **Scalable key management** - Use AWS KMS for enterprise-grade key management
- **Works with all EVM chains** - Compatible with any EVM-based blockchain
- **Optimized address derivation** - Efficiently derives Ethereum addresses from KMS keys
- **Retry mechanism** - Built-in retry logic for AWS API calls
- **Comprehensive logging** - Detailed logging for troubleshooting

## Installation

```bash
npm install purrikey
# or
yarn add purrikey
```

## AWS KMS Setup

To use this package, you need to set up an Asymmetric KMS key with the following specifications:

1. **Key Type**: Asymmetric
2. **Key Usage**: Sign and verify
3. **Key Spec**: ECC_SECG_P256K1

Follow these steps to create a compatible KMS key:

1. Go to AWS KMS in the AWS Console
2. Click "Create key"
3. Select "Asymmetric"
4. Under "Key Usage", select "Sign and verify"
5. Under "Key Spec", select "ECC_SECG_P256K1"
6. Continue with the key creation process, setting appropriate permissions and aliases

## Usage

### Basic usage

```typescript
import { DirectKmsTransactionSigner } from 'purrikey';
import { ethers } from 'ethers';

const provider = new ethers.providers.JsonRpcProvider('');
const signer = new DirectKmsTransactionSigner(
  'arn:aws:kms:us-west-1:123456789012:key/your-key-id',
  provider,
  'us-west-1'
);
```

### Advanced configuration

```typescript
import { DirectKmsTransactionSigner, LogLevel } from 'purrikey';
import { ethers } from 'ethers';

const provider = new ethers.providers.JsonRpcProvider(
  'https://mainnet.infura.io/v3/YOUR_INFURA_KEY'
);
const signer = new DirectKmsTransactionSigner(
  'arn:aws:kms:us-west-1:123456789012:key/your-key-id',
  provider,
  'us-west-1',
  true, // debug mode
  5, // max retries
  1000 // retry delay in ms
);

const balance = await provider.getBalance(await signer.getAddress());
console.log('Balance:', ethers.utils.formatEther(balance), 'ETH');
```

### AWS Credentials

This package uses the AWS SDK for JavaScript v3, which uses the standard AWS credential resolution chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. EC2 instance profile or ECS task role
4. Lambda execution role (if run in AWS Lambda)

Make sure your credentials have the necessary permissions to use the KMS key (`kms:GetPublicKey` and `kms:Sign`).

## API Reference

### `KmsTransactionSigner`

Basic implementation using older KMS signature to address method.

```typescript
new KmsTransactionSigner(
  keyId: string,
  provider?: ethers.providers.Provider,
  region?: string,
  debug?: boolean
)
```

### `DirectKmsTransactionSigner`

Enhanced implementation with more robust error handling and direct public key retrieval.

```typescript
new DirectKmsTransactionSigner(
  keyId: string,
  provider?: ethers.providers.Provider,
  region?: string,
  debug?: boolean,
  maxRetries?: number,
  retryDelay?: number
)
```

Both signers implement the ethers.js Signer interface, so they provide the same methods:

- `getAddress()`: Get the Ethereum address associated with the KMS key
- `signMessage(message)`: Sign a message using the KMS key
- `signTransaction(tx)`: Sign a transaction using the KMS key
- `connect(provider)`: Connect to a new provider
- `sendTransaction(tx)`: Sign and send a transaction

## License

MIT
