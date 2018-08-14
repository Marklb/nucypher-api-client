import base64url from 'base64url'
import * as _EC from 'elliptic'
import { Buffer } from 'safe-buffer'

const EC = _EC.ec
const ec = new EC('secp256k1')

import { NuCypher } from '../src'

const api = new NuCypher('http://127.0.0.1:3000')

const privkey1 = 'DGgxOtqZOrqY-lh_E_L5H2YpNBoT3HEW6whMcVcqf5c='
const privkey2 = '8886EWu9cnGOCoZjNcI1SPEoyOiUTHBYwflfAA5YgCA='


const kp1 = {
  privateKey: Buffer.from(base64url.toBuffer(privkey1)),
  publicKey: Buffer.from(ec.keyFromPrivate(Buffer.from(base64url.toBuffer(privkey1))).getPublic('arr'))
}

const kp2 = {
  privateKey: Buffer.from(base64url.toBuffer(privkey2)),
  publicKey: Buffer.from(ec.keyFromPrivate(Buffer.from(base64url.toBuffer(privkey2))).getPublic('arr'))
}

const main = async () => {
  const label = 'test-2'

  const policy = await api.createPolicy(label, kp1.privateKey, kp2.publicKey)
  console.log('policy', policy)

  const encRes = await api.encryptForPolicy(
    Buffer.from(base64url.toBuffer(policy.policy_pubkey)),
    Buffer.from('Test Message')
  )
  console.log('encRes', encRes)

  const result = await api.decryptForPolicy(
    label,
    Buffer.from(base64url.toBuffer(encRes.message_kit)),
    kp1.publicKey,
    kp2.privateKey,
    Buffer.from(base64url.toBuffer(policy.policy_pubkey)),
    Buffer.from(base64url.toBuffer(encRes.data_source_pubkey))
  )

  console.log(result.toString())

}

main()
