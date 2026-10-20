// Application profile around the paper's cryptographic construction. This is
// not the W3C bbs-2023 Data Integrity wire format.
export const DBAC_EXTENSION = 'https://example.org/a2a-dbac-bbs-bls/v1';
export const DBAC_CHALLENGE_TYP = 'a2a-dbac-challenge+jwt';
export const DBAC_RESPONSE_TYP = 'a2a-dbac-response+jwt';
export const DBAC_SCHEMA = Object.freeze(['role', 'scope', 'epoch', 'mode', 'organization', 'holderLabel']);
export const DBAC_MODES = Object.freeze(['bbs-bls', 'bbs-blind-bls']);
export const epoch = () => new Date().toISOString().slice(0, 10); // Shared UTC day, not a per-user timestamp.
export const requiredDisclosures = mode => ({ 0: 'authorized-agent', 1: 'demo:echo', 2: epoch(), 3: mode });
export const demoAttributes = mode => ['authorized-agent', 'demo:echo', epoch(), mode, 'Competition team', 'Alice / Agent A'];
export const paymentDisclosures = mode => ({ 0: 'authorized-agent', 1: 'payments:pay', 2: epoch(), 3: mode });
export const paymentAttributes = mode => ['authorized-agent', 'payments:pay', epoch(), mode, 'Competition team', 'Alice / Agent A'];

export function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
