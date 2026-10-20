import { createHash } from 'node:crypto';
import { AppError } from '../protocol.mjs';
import { DBAC_SCHEMA } from './policy.mjs';

// bbs-2023 secures the VC. The DBAC proof is an additional mandatory device
// binding check in this application profile, not a replacement cryptosuite.
export const W3C_PAYMENT_PROFILE = 'w3c-bbs-esim-v1';
export const W3C_PAYMENT_SCHEMA = Object.freeze([...DBAC_SCHEMA, 'bindingId']);
export const W3C_DISCLOSED_INDICES = Object.freeze([0, 1, 2, 3, 6]);

// An application transcript hash, separate from the standard cryptosuite's
// RDF canonicalization. Both parties hash exactly the received VC document.
function canonical(value, depth = 0) {
  if (depth > 32) throw new AppError('W3C_BINDING_INVALID', 'W3C 绑定上下文嵌套过深。');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string' && value.isWellFormed()) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(',')}]`;
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`).join(',')}}`;
  throw new AppError('W3C_BINDING_INVALID', 'W3C 绑定上下文必须是规范的 JSON 数据。');
}

// Stable JSON transcript encoding is shared by the independent holder JWS.
// It is deliberately not a substitute for the cryptosuite's RDF canonicalization.
export function transcriptHash(domain, value) {
  if (typeof domain !== 'string' || !/^[a-z0-9:-]+$/.test(domain)) throw new AppError('W3C_BINDING_INVALID', '无效的绑定摘要域。');
  return createHash('sha256').update(`${domain}\0`).update(canonical(value)).digest('base64url');
}

export function presentationHeader(context) {
  return new Uint8Array(createHash('sha256').update(`${W3C_PAYMENT_PROFILE}:presentation-header\0`).update(canonical(context)).digest());
}

export function w3cPresentationHash(derivedCredential) {
  return createHash('sha256').update(`${W3C_PAYMENT_PROFILE}:derived-credential\0`).update(canonical(derivedCredential)).digest('base64url');
}

export function bindingContext(context, derivedCredential) {
  return { ...structuredClone(context), w3cPresentationHash: w3cPresentationHash(derivedCredential) };
}
