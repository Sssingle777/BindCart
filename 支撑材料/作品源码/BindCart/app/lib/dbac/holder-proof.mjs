import { signJws, verifyJws, resolveDid } from '../identity.mjs';
import { AppError, unix } from '../protocol.mjs';
import { transcriptHash, w3cPresentationHash } from './w3c-profile.mjs';

export const HOLDER_PROOF_TYP = 'a2a-w3c-dbac-holder+jwt';
const fail = (code, message) => { throw new AppError(code, message, 403); };

// Only public, signed transcripts are hashed here. The caller owns the private
// KeyObject in Agent A; neither the verifier nor serializable UI state holds it.
export function holderTranscript({ context, verifiableCredential, presentation }) {
  return {
    purpose: 'w3c-dbac-joint-possession-v1',
    contextHash: transcriptHash('w3c-dbac:holder-context:v1', context),
    credentialHash: w3cPresentationHash(verifiableCredential),
    deviceProofHash: transcriptHash('w3c-dbac:holder-device-proof:v1', presentation),
  };
}

export function signHolderProof({ identity, context, verifiableCredential, presentation }) {
  if (identity?.did !== verifiableCredential?.credentialSubject?.holderDid) fail('HOLDER_BINDING_MISMATCH', 'A 的密钥与签发方在凭证中保护的持有者公钥不同。');
  return signJws({ iss: identity.did, aud: context.verifier, iat: context.iat, exp: context.exp,
    ...holderTranscript({ context, verifiableCredential, presentation }) }, identity, HOLDER_PROOF_TYP);
}

export function verifyHolderProof({ holderProof, context, verifiableCredential, presentation, expectedHolderDid = verifiableCredential?.credentialSubject?.holderDid }) {
  if (typeof holderProof !== 'string' || !holderProof) fail('HOLDER_PROOF_REQUIRED', '凭证和设备贡献不能替代持有者 A 的本次私钥签名。');
  let claims;
  try {
    resolveDid(expectedHolderDid);
    claims = verifyJws(holderProof, { typ: HOLDER_PROOF_TYP, expectedDid: expectedHolderDid, purpose: 'authentication' }).payload;
  } catch { fail('HOLDER_SIGNATURE_INVALID', '持有者 A 的签名无效，或签名密钥不是签发方保护的持有者公钥。'); }
  const expected = { iss: expectedHolderDid, aud: context.verifier, iat: context.iat, exp: context.exp,
    ...holderTranscript({ context, verifiableCredential, presentation }) };
  if (transcriptHash('w3c-dbac:holder-claims:v1', claims) !== transcriptHash('w3c-dbac:holder-claims:v1', expected)) fail('HOLDER_BINDING_MISMATCH', 'A 的签名没有绑定本次挑战、验证方、派生凭证和精确设备证明。');
  if (!Number.isSafeInteger(claims.exp) || claims.exp <= unix() || claims.iat > unix() + 5) fail('HOLDER_PROOF_EXPIRED', 'A 的签名已经过期或尚未生效。');
  return { verified: true, keyFingerprint: transcriptHash('w3c-dbac:holder-key:v1', expectedHolderDid), inputHash: transcriptHash('w3c-dbac:holder-claims:v1', expected) };
}
