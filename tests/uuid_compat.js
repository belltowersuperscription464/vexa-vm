"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/js/app.js", "utf8");
const match = source.match(/let uuidFallbackCounter = 0;[\s\S]*?(?=\n  function setText\()/);
assert(match, "randomUuid implementation was not found in app.js");

function loadRandomUuid(cryptoApi) {
  const context = vm.createContext({ window: { crypto: cryptoApi } });
  vm.runInContext(`${match[0]}\nthis.randomUuid = randomUuid;`, context);
  return context.randomUuid;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const nativeValue = "12345678-1234-4123-8123-123456789abc";
assert.equal(loadRandomUuid({ randomUUID: () => nativeValue })(), nativeValue);

const webCryptoFallback = loadRandomUuid({
  getRandomValues(values) {
    values.forEach((_, index) => {
      values[index] = index;
    });
    return values;
  },
});
assert.match(webCryptoFallback(), uuidPattern);

const legacyFallback = loadRandomUuid(undefined);
const firstLegacy = legacyFallback();
const secondLegacy = legacyFallback();
assert.match(firstLegacy, uuidPattern);
assert.match(secondLegacy, uuidPattern);
assert.notEqual(firstLegacy, secondLegacy);

console.log("randomUuid native, Web Crypto fallback, and legacy fallback passed");
