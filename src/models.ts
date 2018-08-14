import { Buffer } from 'safe-buffer'

export const PRIVATE_KEY_LEN = 32
export const PUBLIC_KEY_LEN = 65
export const PUBLIC_KEY_COMPRESSED_LEN = 33

export interface IUmbralKeyPair {
  private_key: string
  public_key: string
}

export interface INuCypherApiResponse {
  /**
   * If the api finished as expected then this is `true`
   */
  success: boolean

  /**
   * Empty unless `success` is `false`
   */
  err_msg: string
}

export interface INuCypherKeyPairResponse extends INuCypherApiResponse {
  /**
   *
   */
  keypair: IUmbralKeyPair
}

export interface INuCypherCreatePolicyResponse extends INuCypherApiResponse {
  /**
   * urlsafe base64 bytes UmbralPublicKey
   */
  policy_pubkey: string

  /**
   * Expiration data of this policy
   */
  policy_expiration_date: string
}

export type INuCypherRevokePolicyResponse = INuCypherApiResponse

export interface INuCypherEncryptForPolicyResponse extends INuCypherApiResponse {
  /**
   * urlsafe base64 bytes UmbralPublicKey
   */
  data_source_pubkey: string

  /**
   * urlsafe base64 bytes MessageKit
   */
  message_kit: string

  /**
   * urlsafe base64 bytes MessageKit signature
   *
   * Not required for reading the message kit
   */
  message_kit_signature: string
}

export interface INuCypherDecryptForPolicyResponse extends INuCypherApiResponse {
  /**
   * urlsafe base64 bytes cleartext
   */
  cleartext: Buffer
}
