/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
const TEXT_ENCODER = new TextEncoder();

export function stringToUtf8Bytes(str) {
  return TEXT_ENCODER.encode(str);
}
