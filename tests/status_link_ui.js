"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/js/app.js", "utf8");
const escapeHelper = source.match(/function escapeHtml\(value\) \{[\s\S]*?(?=\n\n  function asArray\()/);
const arrayHelper = source.match(/function asArray\(value\) \{[\s\S]*?(?=\n\n  function listPayload\()/);
const renderHelper = source.match(/function renderVmLinks\(vm\) \{[\s\S]*?(?=\n\n  function renderVmNetworkSecurity\()/);
assert(escapeHelper, "escapeHtml implementation was not found in app.js");
assert(arrayHelper, "asArray implementation was not found in app.js");
assert(renderHelper, "status-link renderer was not found in app.js");

const target = { innerHTML: "" };
const state = {
  freshStatusLink: {
    tokenId: "link-1",
    url: "https://panel.example/status/one-time-secret",
  },
};
const context = vm.createContext({
  state,
  target,
  $: (selector) => selector === "#vm-status-links" ? target : null,
  dateTime: (value) => String(value),
});
vm.runInContext(
  `${escapeHelper[0]}\n${arrayHelper[0]}\n${renderHelper[0]}\nthis.renderVmLinks = renderVmLinks;`,
  context,
);

const record = {
  id: "link-1",
  name: "Customer status",
  scopes: ["status:read", "power:write"],
  expires_at: 1_800_000_000,
};
context.renderVmLinks({ status_tokens: [record] });
assert.match(target.innerHTML, /https:\/\/panel\.example\/status\/one-time-secret/);
assert.match(target.innerHTML, /data-copy-status-link/);
assert.match(target.innerHTML, /shown only in this browser until refresh/);

state.freshStatusLink = null;
context.renderVmLinks({ status_links: [record] });
assert.doesNotMatch(target.innerHTML, /one-time-secret/);
assert.match(target.innerHTML, /URL is shown only when created/);

state.freshStatusLink = {
  tokenId: "link-1",
  url: "https://panel.example/status/<script>alert(1)</script>",
};
context.renderVmLinks({ status_tokens: [record] });
assert.doesNotMatch(target.innerHTML, /<script>/);
assert.match(target.innerHTML, /&lt;script&gt;/);

console.log("fresh status URL rendering, one-time hiding, and escaping passed");
