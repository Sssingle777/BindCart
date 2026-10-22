/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import {klona} from 'klona';
import {parsePointer} from './pointer.js';
import {relabelBlankNodes} from './canonicalize.js';
import {toDeskolemizedNQuads} from './skolemize.js';

export function selectJsonLd({document, pointers, includeTypes = true} = {}) {
  if(!(document && typeof document === 'object')) {
    throw new TypeError('"document" must be an object.');
  }
  if(!Array.isArray(pointers)) {
    throw new TypeError('"pointers" must be an array.');
  }
  if(pointers.length === 0) {
    // no pointers, so no frame
    return null;
  }

  // track arrays to make them dense after selection
  const arrays = [];

  // perform selection
  const selectionDocument = {'@context': klona(document['@context'])};
  _initSelection(
    {selection: selectionDocument, source: document, includeTypes});
  for(const pointer of pointers) {
    // parse pointer into individual paths
    const paths = parsePointer(pointer);
    if(paths.length === 0) {
      // whole document selected
      return klona(document);
    }
    _selectPaths({
      document, pointer, paths, selectionDocument, arrays, includeTypes
    });
  }

  // make any sparse arrays dense
  for(const array of arrays) {
    let i = 0;
    while(i < array.length) {
      if(array[i] === undefined) {
        array.splice(i, 1);
        continue;
      }
      i++;
    }
  }

  return selectionDocument;
}

export async function selectCanonicalNQuads({
  document, pointers, labelMap, options
} = {}) {
  // 1. Perform selection on compact, skolemized JSON-LD using JSON pointers.
  const selection = selectJsonLd({document, pointers});

  // 2. Get deskolemized N-Quads for the selection.
  const deskolemizedNQuads = await toDeskolemizedNQuads(
    {document: selection, options});

  // 3. Relabel blank nodes with canonical labels using the label map.
  const nquads = relabelBlankNodes({nquads: deskolemizedNQuads, labelMap});

  // 4. Return selected canonical N-Quads.
  return {selection, deskolemizedNQuads, nquads};
}

function _selectPaths({
  document, pointer, paths, selectionDocument, arrays, includeTypes
} = {}) {
  // make pointer path in selection document
  let parentValue = document;
  let value = parentValue;
  let selectedParent = selectionDocument;
  let selectedValue = selectedParent;
  for(const path of paths) {
    selectedParent = selectedValue;
    parentValue = value;

    // get next document value
    value = parentValue[path];
    if(value === undefined) {
      throw new TypeError(
        `JSON pointer "${pointer}" does not match document.`);
    }

    // get next value selection
    selectedValue = selectedParent[path];
    if(selectedValue === undefined) {
      if(Array.isArray(value)) {
        selectedValue = [];
        arrays.push(selectedValue);
      } else {
        selectedValue = _initSelection({source: value, includeTypes});
      }
      selectedParent[path] = selectedValue;
    }
  }

  // path traversal complete, compute selected value
  if(typeof value !== 'object') {
    // literal selected
    selectedValue = value;
  } else if(Array.isArray(value)) {
    // full array selected
    selectedValue = klona(value);
  } else {
    // object selected, blend with `id` / `type` / `@context`
    selectedValue = {...selectedValue, ...klona(value)};
  }

  // add selected value to selected parent
  selectedParent[paths.at(-1)] = selectedValue;
}

function _initSelection({selection = {}, source, includeTypes}) {
  // must include non-blank node IDs
  if(source.id && !source.id.startsWith('_:')) {
    selection.id = source.id;
  }
  // include types if directed to do so
  if(includeTypes && source.type) {
    selection.type = source.type;
  }
  return selection;
}
