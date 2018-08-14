import * as BN from 'bn.js'
import { Buffer } from 'safe-buffer'

import { PUBLIC_KEY_COMPRESSED_LEN } from './models'

/**
 * Compress a public key
 *
 * @param publicKey
 */
export const compressPublicKey = (publicKey: Buffer): Buffer => {
  if (publicKey.length === PUBLIC_KEY_COMPRESSED_LEN) {
    return publicKey
  }
  // TODO: Do this with the buffer directly instead of converting to string
  const tmp = publicKey.toString('hex').slice(2)
  const xHex = tmp.replace(tmp.slice(tmp.length / 2), '')
  const yHex = tmp.slice(tmp.length / 2)

  const bnX = new BN(xHex, 16)

  const bnY = new BN(yHex, 16)

  let pubkeyHex
  if (bnY.isOdd()) {
    pubkeyHex = '03' + bnX.toString(16)
  } else {
    pubkeyHex = '02' + bnX.toString(16)
  }

  return Buffer.from(pubkeyHex, 'hex')
}
