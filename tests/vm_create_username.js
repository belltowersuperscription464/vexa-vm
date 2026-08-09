"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/js/app.js", "utf8");
const helpers = source.match(/function guestAdministratorDefault\(image = \{\}\) \{[\s\S]*?(?=\n\n  function updateCreateAccessMode\()/);
assert(helpers, "image-aware guest administrator helpers were not found in app.js");

const context = vm.createContext({});
vm.runInContext(
  `${helpers[0]}\nthis.guestAdministratorDefault = guestAdministratorDefault;\nthis.updateCreateAdministratorDefault = updateCreateAdministratorDefault;`,
  context,
);

assert.equal(context.guestAdministratorDefault({ os_family: "Ubuntu Linux" }), "root");
assert.equal(context.guestAdministratorDefault({ os_family: "Windows Server 2025" }), "Administrator");
assert.equal(context.guestAdministratorDefault({ os_family: "WINDOWS" }), "Administrator");
assert.equal(context.guestAdministratorDefault({ os_family: "RouterOS" }), "vexa-admin");

const username = { value: "root", dataset: {} };
const form = { elements: { username } };
context.updateCreateAdministratorDefault(form, { os_family: "windows" });
assert.equal(username.value, "Administrator");
context.updateCreateAdministratorDefault(form, { os_family: "linux" });
assert.equal(username.value, "root", "an untouched generated default should follow image changes");

username.value = "deployment-admin";
username.dataset.userEdited = "true";
context.updateCreateAdministratorDefault(form, { os_family: "windows" });
assert.equal(username.value, "deployment-admin", "a deliberate administrator name must be preserved");

console.log("VM create administrator defaults follow the image and preserve deliberate edits");
