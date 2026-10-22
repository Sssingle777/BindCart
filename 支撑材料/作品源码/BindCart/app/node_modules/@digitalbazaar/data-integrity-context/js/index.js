/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const contextV1 = require('./data-integrity-v1');
const contextV2 = require('./data-integrity-v2');
const constants = require('./constants');
const {
  CONTEXT_URL, DATA_INTEGRITY_CONTEXT_V1_URL, DATA_INTEGRITY_CONTEXT_V2_URL,
  CBORLD_VALUE
} = constants;

const contexts = new Map();
contexts.set(DATA_INTEGRITY_CONTEXT_V1_URL, contextV1);
contexts.set(DATA_INTEGRITY_CONTEXT_V2_URL, contextV2);

const appContextMap = new Map();
appContextMap.set(CONTEXT_URL, CBORLD_VALUE);

module.exports = {
  constants,
  contexts,
  appContextMap,
  DATA_INTEGRITY_CONTEXT_V1_URL,
  DATA_INTEGRITY_CONTEXT_V2_URL,
  CONTEXT_URL,
  CONTEXT: contextV2
};
