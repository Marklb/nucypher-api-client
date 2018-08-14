import base64url from 'base64url'
import fetch from 'cross-fetch'
import { Buffer } from 'safe-buffer'

import { INuCypherCreatePolicyResponse, INuCypherEncryptForPolicyResponse, INuCypherRevokePolicyResponse } from './models'
import { compressPublicKey } from './utils'

export class NuCypher {

  private version = '3.0'

  private _commonHeaders = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }

  constructor(
    public apiPath = 'http://127.0.0.1:3000'
  ) { }

  /**
   * Keys generated from `elliptic` package also work, for
   * generating keys in the browser instead.
   */
  public async genKeyPair() {
    const url = `${this.apiPath}/api/v${this.version}/gen_keypair`

    const res = await fetch(url)

    const policy = await res.json()

    return policy.keypair
  }

  /**
   *
   * NOTE: `policy_expiration` will eventually be a date, but for now is just
   *  number of days as a positive integer.
   *
   * TODO: Change this api call to `grant`, because the `grant` method is what
   *  returns the policy public key, or something else that makes sense.
   *
   * TODO: Set `n`, `m`, and `policy_expiration` to reasonable or configurable
   *  defaults.
   *
   * @param label
   * @param alice_privkey
   * @param bob_pubkey
   * @param m
   * @param n
   * @param policy_expiration
   */
  public async createPolicy(
    label: string,
    alice_privkey: Buffer,
    bob_pubkey: Buffer,
    m: number = 1,
    n: number = 1,
    policy_expiration: number = 365
  ): Promise<INuCypherCreatePolicyResponse> {
    const url = `${this.apiPath}/api/v${this.version}/create_policy`

    const body = {
      label,
      alice_privkey: base64url(alice_privkey) + '=',
      bob_pubkey: base64url(compressPublicKey(bob_pubkey)),
      m, n, policy_expiration
    }

    const res = await fetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: this._commonHeaders
    })

    const policy = await res.json()

    if (!policy || !policy.success) {
      throw new Error(`Error creating policy: ${(policy) ? policy.err_msg : ''}`)
    }

    return policy
  }

  /**
   *
   * @param label
   * @param alice_privkey
   * @param bob_pubkey
   */
  public async revokePolicy(
    label: string,
    alice_privkey: Buffer,
    bob_pubkey: Buffer,
  ): Promise<INuCypherRevokePolicyResponse> {
    const url = `${this.apiPath}/api/v${this.version}/revoke_policy`
    const body = {
      label,
      alice_privkey: base64url(alice_privkey) + '=',
      bob_pubkey: base64url(compressPublicKey(bob_pubkey))
    }

    const res = await fetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: this._commonHeaders
    })

    const result = await res.json()

    if (!result || !result.success) {
      throw new Error(`Error revoking policy: ${(result) ? result.err_msg : ''}`)
    }

    return result
  }

  /**
   *
   * @param policy_pubkey
   * @param plaintext
   */
  public async encryptForPolicy(
    policy_pubkey: Buffer,
    plaintext: Buffer
  ): Promise<INuCypherEncryptForPolicyResponse> {
    const url = `${this.apiPath}/api/v${this.version}/encrypt_for_policy`
    const body = {
      policy_pubkey: base64url(compressPublicKey(policy_pubkey)),
      plaintext: plaintext.toString('base64')
    }

    const res = await fetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: this._commonHeaders
    })

    const result = await res.json()

    if (!result || !result.success) {
      throw new Error(`Error encrypting for policy: ${(result) ? result.err_msg : ''}`)
    }

    return result
  }

  /**
   *
   * @param label
   * @param message_kit
   * @param alice_pubkey
   * @param bob_privkey
   * @param policy_pubkey
   * @param data_source_pubkey
   */
  public async decryptForPolicy(
    label: string,
    message_kit: Buffer,
    alice_pubkey: Buffer,
    bob_privkey: Buffer,
    policy_pubkey: Buffer,
    data_source_pubkey: Buffer
  ): Promise<Buffer> {
    const url = `${this.apiPath}/api/v${this.version}/decrypt_for_policy`
    const body = {
      label,
      message_kit: base64url(message_kit),
      alice_pubkey: base64url(compressPublicKey(alice_pubkey)),
      bob_privkey: base64url(bob_privkey) + '=',
      policy_pubkey: base64url(compressPublicKey(policy_pubkey)),
      data_source_pubkey: base64url(compressPublicKey(data_source_pubkey))
    }

    const res = await fetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: this._commonHeaders
    })

    const result = await res.json()

    if (!result || !result.success) {
      throw new Error(`Error decrypting for policy: ${(result) ? result.err_msg : ''}`)
    }

    return Buffer.from(result.cleartext, 'base64')
  }

}
