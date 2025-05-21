import { BigNumber } from 'ethers';
import { CURVE_N, HALF_N } from '../../src/utils/constants';
import { decodeDER, normaliseSignature } from '../../src/utils/signature';

describe('Signature utils', () => {
  describe('normaliseSignature', () => {
    const rHex = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

    const highSHex = '0xd97bfcd60a78716f381c12d97a9c22fa15df48510da977322eb5ba1add10ebb2';

    const lowSHex = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

    it('should normalize high-s values', () => {
      const result = normaliseSignature(rHex, highSHex);

      expect(BigNumber.from(result.s).lte(HALF_N)).toBe(true);

      expect(result.recoveryParam).toBe(1);

      expect(result.v).toBe(28);

      const expectedS = CURVE_N.sub(BigNumber.from(highSHex));
      expect(BigNumber.from(result.s).eq(expectedS)).toBe(true);
    });

    it('should not modify low-s values', () => {
      const result = normaliseSignature(rHex, lowSHex);

      expect(result.s).toBe(ethers.utils.hexZeroPad(lowSHex, 32));

      expect(result.recoveryParam).toBe(0);

      expect(result.v).toBe(27);
    });

    it('should respect provided recovery parameter', () => {
      const result = normaliseSignature(rHex, lowSHex, undefined, 1);

      expect(result.recoveryParam).toBe(1);

      expect(result.v).toBe(28);
    });

    it('should handle chainId for EIP-155 compatibility', () => {
      const chainId = 1;
      const result = normaliseSignature(rHex, lowSHex, chainId);

      expect(result.v).toBe(35 + 0 + chainId * 2);
    });
  });

  describe('decodeDER', () => {
    it('should correctly decode a valid DER signature', () => {
      const r = Buffer.alloc(32, 1);
      const s = Buffer.alloc(32, 2);

      const derSignature = Buffer.concat([
        Buffer.from([0x30, 0x44]),
        Buffer.from([0x02, 0x20]),
        r,
        Buffer.from([0x02, 0x20]),
        s,
      ]);

      const decoded = decodeDER(derSignature);

      expect(decoded.r).toBe('0x' + r.toString('hex'));
      expect(decoded.s).toBe('0x' + s.toString('hex'));
    });

    it('should throw for invalid DER signatures', () => {
      const invalidDer1 = Buffer.from([0x31, 0x44, 0x02, 0x20]);
      expect(() => decodeDER(invalidDer1)).toThrow(
        'Invalid DER signature: Expected sequence tag 0x30'
      );

      const invalidDer2 = Buffer.from([0x30, 0x44, 0x03, 0x20]);
      expect(() => decodeDER(invalidDer2)).toThrow(
        'Invalid DER signature: Expected integer tag 0x02 for r'
      );
    });

    it('should handle DER signatures with leading zeros in r or s', () => {
      const r = Buffer.concat([Buffer.alloc(2, 0), Buffer.alloc(30, 1)]);
      const s = Buffer.alloc(32, 2);

      const derSignature = Buffer.concat([
        Buffer.from([0x30, 0x44]),
        Buffer.from([0x02, 0x20]),
        r,
        Buffer.from([0x02, 0x20]),
        s,
      ]);

      const decoded = decodeDER(derSignature);

      const expectedR =
        '0x' + Buffer.concat([Buffer.alloc(2, 0), Buffer.alloc(30, 1)]).toString('hex');

      expect(decoded.r).toBe(expectedR);
    });
  });
});

const ethers = {
  utils: {
    hexZeroPad: (hex: string, length: number) => {
      if (!hex.startsWith('0x')) hex = '0x' + hex;
      const byte_length = length * 2;
      const value = hex.slice(2);
      return '0x' + '0'.repeat(Math.max(0, byte_length - value.length)) + value;
    },
  },
};
