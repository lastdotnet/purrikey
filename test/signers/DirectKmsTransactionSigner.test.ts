import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import { BigNumber, ethers } from 'ethers';
import { DirectKmsTransactionSigner } from '../../src';
import { CURVE_N, HALF_N } from '../../src/utils/constants';
import { normaliseSignature } from '../../src/utils/signature';

const kmsMock = mockClient(KMSClient);

describe('DirectKmsTransactionSigner', () => {
  const TEST_KEY_ID = 'test-key-id';
  const TEST_REGION = 'us-west-2';
  const knownHighS = '0xd97bfcd60a78716f381c12d97a9c22fa15df48510da977322eb5ba1add10ebb2';

  let signer: DirectKmsTransactionSigner;

  beforeEach(() => {
    kmsMock.reset();

    signer = new DirectKmsTransactionSigner(TEST_KEY_ID, undefined, TEST_REGION, false);

    const publicKey = Buffer.from(
      '041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      'hex'
    );

    kmsMock.on(GetPublicKeyCommand).resolves({
      PublicKey: publicKey,
      KeyId: TEST_KEY_ID,
    });

    const r = Buffer.alloc(32).fill(1);
    const s = Buffer.alloc(32).fill(2);
    const derSignature = Buffer.concat([
      Buffer.from([0x30, 0x44]),
      Buffer.from([0x02, 0x20]),
      r,
      Buffer.from([0x02, 0x20]),
      s,
    ]);

    kmsMock.on(SignCommand).resolves({
      Signature: derSignature,
      KeyId: TEST_KEY_ID,
    });
  });

  describe('Basic functionality', () => {
    it('should initialize correctly with provided values', () => {
      expect((signer as any).kmsKeyId).toBe(TEST_KEY_ID);
      expect((signer as any).region).toBe(TEST_REGION);
      expect((signer as any).debug).toBe(false);
    });

    it('should return the correct address from KMS public key', async () => {
      const publicKey = Buffer.from(
        '041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        'hex'
      );
      const expectedAddress = ethers.utils.computeAddress(publicKey);

      const address = await signer.getAddress();

      expect(address).toBe(expectedAddress);
      expect(kmsMock.calls()).toHaveLength(1);
    });

    it('should cache the address after first retrieval', async () => {
      const publicKey = Buffer.from(
        '041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        'hex'
      );
      const expectedAddress = ethers.utils.computeAddress(publicKey);

      await signer.getAddress();
      kmsMock.resetHistory();

      const address = await signer.getAddress();

      expect(address).toBe(expectedAddress);
      expect(kmsMock.calls()).toHaveLength(0);
    });
  });

  describe('signature normalization', () => {
    it('should normalize signatures with s > HALF_N', () => {
      const r = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const s = knownHighS;
      const recoveryParam = 0;

      const normalized = normaliseSignature(r, s, undefined, recoveryParam);

      expect(BigNumber.from(normalized.s).lte(HALF_N)).toBe(true);
      expect(normalized.v).toBe(28);

      const expectedS = CURVE_N.sub(BigNumber.from(knownHighS));
      expect(BigNumber.from(normalized.s).eq(expectedS)).toBe(true);
    });

    it('should not modify signatures that already have low-s values', () => {
      const r = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
      const lowS = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const recoveryParam = 1;

      const normalized = normaliseSignature(r, lowS, undefined, recoveryParam);

      expect(normalized.r).toBe(r);
      expect(normalized.s).toBe(lowS);
      expect(normalized.v).toBe(28);
    });
  });

  describe('Transaction handling', () => {
    it('should throw when no chainId is available', async () => {
      const tx = {
        to: '0x1234567890123456789012345678901234567890',
        data: '0x',
        gasLimit: BigNumber.from(21000),
      };

      await expect(signer.signTransaction(tx)).rejects.toThrow('Transaction missing chainId');
    });

    it('should return a new instance with the connected provider', () => {
      const mockProvider = {
        getNetwork: jest.fn(),
        getFeeData: jest.fn(),
      } as unknown as ethers.providers.Provider;

      const connectedSigner = signer.connect(mockProvider);

      expect(connectedSigner).toBeInstanceOf(DirectKmsTransactionSigner);
      expect(connectedSigner).not.toBe(signer);
      expect((connectedSigner as any).provider).toBe(mockProvider);
    });
  });
});
