/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import jsonld from 'jsonld';
import {klona} from 'klona';

// FIXME: consider accepting optional skolem `prefix` to use instead of
// `urn:bnid` to help avoid paranoid clashes
export function deskolemizeNQuads({nquads} = {}) {
  const mutated = [];
  for(const nq of nquads) {
    if(!nq.includes('<urn:bnid:')) {
      mutated.push(nq);
    } else {
      mutated.push(nq.replace(/(<urn:bnid:([^>]+)>)/g, '_:$2'));
    }
  }
  return mutated;
}

// FIXME: consider accepting optional skolem `prefix` to use instead of
// `urn:bnid` to help avoid paranoid clashes
export function skolemizeNQuads({nquads} = {}) {
  // FIXME:
  // replacer = (m, s1, s2) => `<{$prefix}${s2}>`;

  const mutated = [];
  for(const nq of nquads) {
    if(!nq.includes('_:')) {
      mutated.push(nq);
    } else {
      mutated.push(nq.replace(/(_:([^\s]+))/g, '<urn:bnid:$2>'));
    }
  }
  return mutated;
}

// FIXME: consider accepting optional skolem `prefix` to use instead of
// `urn:bnid` to help avoid paranoid clashes
export async function skolemizeCompactJsonLd({document, options} = {}) {
  if(!(typeof document === 'object' && document?.['@context'])) {
    throw new TypeError(
      '"document" must be an object representing a compact JSON-LD document ' +
      'with an "@context".');
  }

  // 1. Expand `document`.
  const expanded = await jsonld.expand(document, {safe: true, ...options});

  // 2. Skolemize expanded document.
  const skolemized = {expanded: null, compact: null};
  skolemized.expanded = skolemizeExpandedJsonLd({expanded, options});

  // 3. Generate skolemized compact document.
  skolemized.compact = await jsonld.compact(
    skolemized.expanded, document['@context'], {safe: true, ...options});

  // 4. Return expanded and compact skolemized forms of `document`.
  return skolemized;
}

// FIXME: consider accepting optional skolem `prefix` to use instead of
// `urn:bnid` to help avoid paranoid clashes
export function skolemizeExpandedJsonLd({
  expanded, labeler = {
    prefix: `urn:bnid:`, random: crypto.randomUUID(), count: 0
  }
} = {}) {
  const skolemized = [];
  for(const element of expanded) {
    // copy literals directly
    if(typeof element !== 'object' || element?.['@value'] !== undefined) {
      skolemized.push(klona(element));
      continue;
    }

    // non-literal, must recurse...
    const skolemizedNode = {};
    for(const property in element) {
      const value = element[property];
      skolemizedNode[property] = Array.isArray(value) ?
        skolemizeExpandedJsonLd({expanded: value, labeler}) :
        skolemizeExpandedJsonLd({expanded: [value], labeler})[0];
    }

    // skolemize node
    if(skolemizedNode['@id'] === undefined) {
      // generate randomized skolem ID
      skolemizedNode['@id'] =
        `${labeler.prefix}_${labeler.random}_${labeler.count++}`;
    } else if(skolemizedNode['@id'].startsWith('_:')) {
      // preserve existing bnode identifier in skolem ID; it may be shared
      skolemizedNode['@id'] =
        `${labeler.prefix}${skolemizedNode['@id'].slice(2)}`;
    }

    skolemized.push(skolemizedNode);
  }

  return skolemized;
}

export async function toDeskolemizedNQuads({document, options} = {}) {
  // 1. Convert skolemized doc to RDF to produce skolemized N-Quads.
  const rdfOptions = {
    rdfDirection: 'i18n-datatype',
    safe: true,
    ...options,
    format: 'application/n-quads'
  };
  const rdf = await jsonld.toRDF(document, rdfOptions);

  // 2. Split N-Quads into arrays for deskolemization.
  const skolemized = rdf.split('\n').slice(0, -1).map(nq => nq + '\n');

  // 3. Return deskolemize N-Quads.
  return deskolemizeNQuads({nquads: skolemized});
}
