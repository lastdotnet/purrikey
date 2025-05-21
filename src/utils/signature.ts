import { hexZeroPad } from '@ethersproject/bytes';
import { keccak256 } from '@ethersproject/keccak256';
import { encode as rlpEncode } from '@ethersproject/rlp';
import { BigNumber, ethers } from 'ethers';
import { CURVE_N, HALF_N } from './constants';
import { defaultLogger } from './logging';
import { NormalisedSig } from './types';

export function normaliseSignature(rHex: string, sHex: string, chainId?: number, yParity?: number): NormalisedSig {
  rHex = rHex.startsWith('0x') ? rHex : `0x${rHex}`;
  sHex = sHex.startsWith('0x') ? sHex : `0x${sHex}`;

  const r = BigNumber.from(rHex);
  let s = BigNumber.from(sHex);

  let recoveryParam = yParity ?? 0;

  if (s.gt(HALF_N)) {
    defaultLogger.debug('Canonicalising high-s signature', {
      originalS: sHex.substring(0, 10) + '...',
      chainId: chainId || 0,
    });

    s = CURVE_N.sub(s);
    recoveryParam = recoveryParam ^ 1;
  }

  let v: number;
  if (chainId && chainId > 0) {
    v = 35 + recoveryParam + chainId * 2;

    if (chainId > 100) {
      defaultLogger.debug('High chain ID v calculation', {
        chainId,
        recoveryParam,
        v,
      });
    }
  } else {
    v = 27 + recoveryParam;
  }

  const rNormalized = hexZeroPad(r.toHexString(), 32);
  const sNormalized = hexZeroPad(s.toHexString(), 32);

  const _vs = hexZeroPad(s.or(BigNumber.from(recoveryParam).shl(255)).toHexString(), 32);

  return {
    r: rNormalized,
    s: sNormalized,
    v,
    recoveryParam,
    _vs,
    yParityAndS: _vs,
    compact: rNormalized + sNormalized.substring(2),
  };
}

export function decodeDER(derSignature: Buffer | Uint8Array): { r: string; s: string } {
  const signatureBuffer = Buffer.isBuffer(derSignature) ? derSignature : Buffer.from(derSignature);

  let position = 0;

  if (signatureBuffer[position++] !== 0x30) {
    throw new Error('Invalid DER signature: Expected sequence tag 0x30');
  }

  position++;

  if (signatureBuffer[position++] !== 0x02) {
    throw new Error('Invalid DER signature: Expected integer tag 0x02 for r');
  }

  const rLength = signatureBuffer[position++];
  let rValue = signatureBuffer.slice(position, position + rLength);
  position += rLength;

  if (signatureBuffer[position++] !== 0x02) {
    throw new Error('Invalid DER signature: Expected integer tag 0x02 for s');
  }

  const sLength = signatureBuffer[position++];
  let sValue = signatureBuffer.slice(position, position + sLength);

  while (rValue.length > 1 && rValue[0] === 0x00) {
    rValue = rValue.slice(1);
  }

  while (sValue.length > 1 && sValue[0] === 0x00) {
    sValue = sValue.slice(1);
  }

  const rPadded = Buffer.alloc(32, 0);
  rValue.copy(rPadded, 32 - rValue.length);

  const sPadded = Buffer.alloc(32, 0);
  sValue.copy(sPadded, 32 - sValue.length);

  const r = '0x' + rPadded.toString('hex');
  const s = '0x' + sPadded.toString('hex');

  return { r, s };
}

export function hashEip1559(fields: ReadonlyArray<any>): string {
  return keccak256(ethers.utils.concat(['0x02', rlpEncode(fields)]));
}

export async function derToSignature(
  derSig: Buffer | Uint8Array,
  msgHash: string,
  chainId: number,
  expectedAddr: string
): Promise<ethers.Signature> {
  const { r, s } = decodeDER(derSig);
  const msgHashBytes = ethers.utils.arrayify(msgHash);

  defaultLogger.debug('DER to Signature conversion', {
    chainId,
    expectedAddr: expectedAddr.substring(0, 10) + '...',
    rPrefix: r.substring(0, 10) + '...',
    sPrefix: s.substring(0, 10) + '...',
  });

  for (let recoveryParam = 0; recoveryParam <= 1; recoveryParam++) {
    try {
      const normalizedSig = normaliseSignature(r, s, chainId, recoveryParam);
      const recoveredAddr = ethers.utils.recoverAddress(msgHashBytes, normalizedSig);

      if (recoveredAddr.toLowerCase() === expectedAddr.toLowerCase()) {
        defaultLogger.debug('Found matching recovery param', {
          recoveryParam,
          v: normalizedSig.v,
        });

        return normalizedSig as ethers.Signature;
      }
    } catch (e) {
      defaultLogger.debug('Recovery attempt failed', {
        recoveryParam,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  defaultLogger.debug('Trying with canonical s values for recovery');

  const sBN = BigNumber.from(s);
  const canonicalS = CURVE_N.sub(sBN).toHexString();

  for (let recoveryParam = 0; recoveryParam <= 1; recoveryParam++) {
    try {
      const normalizedSig = normaliseSignature(r, canonicalS, chainId, recoveryParam);
      const recoveredAddr = ethers.utils.recoverAddress(msgHashBytes, normalizedSig);

      if (recoveredAddr.toLowerCase() === expectedAddr.toLowerCase()) {
        defaultLogger.debug('Found match with canonical s', {
          recoveryParam,
          v: normalizedSig.v,
          usedCanonical: true,
        });

        return normalizedSig as ethers.Signature;
      }
    } catch (e) {
      defaultLogger.debug('Recovery attempt with canonical s failed', {
        error: e instanceof Error ? e.message : String(e)
      });
    }
  }

  throw new Error(`Failed to recover the expected address ${expectedAddr} from signature`);
}