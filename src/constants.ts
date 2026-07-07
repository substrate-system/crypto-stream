import { type SupportedEncodings } from 'uint8arrays'

export const IV_LENGTH = 12
export const encoder = new TextEncoder()
export const KEY_LENGTH = 16
export const MAIN_KEY_LENGTHS = [KEY_LENGTH, 32]
export const DEFAULT_KEY_ENCODING:SupportedEncodings = 'base64url'
export const TAG_LENGTH = 16
