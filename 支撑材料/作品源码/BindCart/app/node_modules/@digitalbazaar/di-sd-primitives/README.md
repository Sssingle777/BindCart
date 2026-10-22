# Data Integrity Selective Disclosure Primitives _(@digitalbazaar/di-sd-primitives)_

[![Build Status](https://img.shields.io/github/actions/workflow/status/digitalbazaar/di-sd-primitives/main.yaml)](https://github.com/digitalbazaar/di-sd-primitives/actions/workflow/main.yaml)
[![Coverage Status](https://img.shields.io/codecov/c/github/digitalbazaar/di-sd-primitives)](https://codecov.io/gh/digitalbazaar/di-sd-primitives)
[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/di-sd-primitives.svg)](https://npm.im/@digitalbazaar/di-sd-primitives)

> DI-SD (Pronounced "DICED") (Data Integrity Selective Disclosure) Primitives for use
with Data Integrity selective disclosure cryptosuites and jsonld-signatures.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

For use with https://github.com/digitalbazaar/jsonld-signatures v11.2 and above.

See also related specs:

* [Verifiable Credential Data Integrity](https://w3c.github.io/vc-data-integrity/)

## Security

TBD

## Install

This software requires and supports maintained recent versions of Node.js and
browsers. Updates may remove support for older unmaintained platform versions.
Please use dependency version lock files and testing to ensure compatibility
with this software.

To install from NPM:

```sh
npm install @digitalbazaar/di-sd-primitives
```

To install locally (for development):

```sh
git clone https://github.com/digitalbazaar/di-sd-primitives.git
cd di-sd-primitives
npm install
```

## Usage

The following code snippet provides a complete example of digitally signing
a verifiable credential using this library:

```javascript
import * as primitives from '@digitalbazaar/di-sd-primitives';

// canonize a document (e.g., Verifiable Credential (VC)) and replace blank
// node IDs that are informationally decoupled from the data in the document
const hmac = await primitives.createHmac({key: hmacKey});
const labelMapFactoryFunction =
  primitives.createHmacIdLabelMapFunction({hmac});
// returns an array of nquads
const result = await primitives.labelReplacementCanonicalizeJsonLd(
  {document: credential, labelMapFactoryFunction, options: {documentLoader}});

// canonize a document (e.g., VC) and replace blank node IDs with any
// values; most useful for verifiers to use a label map provided in a
// selectively disclosed proof (verifiers do not get the HMAC key, so they
// cannot generate *any* HMAC'd ID, they only get the disclosed labels)
const labelMap = new Map([
  ['c14n0', 'uSomeBase64UrlHMACDigest1'],
  ['c14n1', 'uSomeBase64UrlHMACDigest2'],
  ['c14n2', 'uSomeBase64UrlHMACDigest3']
]);
const labelMapFactoryFunction = primitives.createLabelMapFunction({labelMap});
// returns an array of nquads
const result = await primitives.labelReplacementCanonicalizeJsonLd(
  {document: credential, labelMapFactoryFunction, options: {documentLoader}});

// skolemize a document (e.g., VC), which replaces blank node IDs with stable
// URL IDs; most useful for performing selecting portions of a JSON-LD document
// and finding the matching selected N-Quads;
// `result` has `{expanded, compact}` for both expanded and compact forms of
// the skolemized JSON-LD document; the expanded form is often deskolemized to
// N-Quads and then canonicalized to produce canonical N-Quads and a mapping
// from the deskolemized blank node IDs to the canonical IDs; the compact form
// can then have N-many selection operations performed on it with the selection
// outputs too being converted to deskolemized N-Quads which can be mapped to
// matching canonical N-Quads
const result = await skolemizeCompactJsonLd({document, options});

// get deskolemized N-Quads from a document; most useful for converting
// previously skolemized expanded JSON-LD documents to canonicalize and
// generate a map of stable identifiers or for converting previously skolemized
// compact JSON-LD documents after selecting a portion of them for selective
// disclosure; see `selectCanonicalNQuads` primitive
const deskolemizedNQuads = await toDeskolemizedNQuads(
  {document: skolemizedExpandedOrCompactJsonLd, options});

// canonize N-Quads and replace blank node IDs and get a label mapping from
// the original blank node IDs to the new ones; most useful for canonizing
// deskolemized N-Quads to produce a
const hmac = await primitives.createHmac({key: hmacKey});
const labelMapFactoryFunction =
  primitives.createHmacIdLabelMapFunction({hmac});
// returns an object with `{nquads, labelMap}`, the array of nquads and the
// mapping from input blank node IDs to output blank node IDs (after the
// canonical IDs have been replaced using the given replacement label map)
const result = await primitives.labelReplacementCanonicalizeNQuads(
  {nquads, labelMapFactoryFunction, options: {documentLoader}});

// use JSON pointers to select a specific part of a JSON-LD document
// (e.g., VC); can be used on a regular or skolemized compact JSON-LD document
const pointers = [
  '/credentialSubject/driverLicense/dateOfBirth',
  '/credentialSubject/driverLicense/expirationDate'
];
const result = await primitives.selectJsonLd(
  {document: credential, pointers});
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © 2023 Digital Bazaar
