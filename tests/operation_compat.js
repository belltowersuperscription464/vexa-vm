"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("static/js/app.js", "utf8");
const errorClass = source.match(/class ApiError extends Error \{[\s\S]*?(?=\n\n  function cookie\()/);
const terminalHelper = source.match(/function operationTerminalError\(operation\) \{[\s\S]*?(?=\n\n  function clamp\()/);
const protectedFollower = source.match(/async function followOperation\(payload, onUpdate = \(\) => \{\}\) \{[\s\S]*?(?=\n\n  function setLiveState\()/);
const publicFollower = source.match(/async function followPublicOperation\(payload\) \{[\s\S]*?(?=\n\n  function openPublicAction\()/);
assert(errorClass, "ApiError implementation was not found in app.js");
assert(terminalHelper, "operation terminal-state helper was not found in app.js");
assert(protectedFollower, "protected operation follower was not found in app.js");
assert(publicFollower, "public operation follower was not found in app.js");

const queuedResponses = [];
let apiCalls = 0;
const context = vm.createContext({
  window: { setTimeout: (callback) => callback() },
  setTimeout: (callback) => callback(),
  showPublicOperation: () => {},
  apiFirst: async () => {
    apiCalls += 1;
    const next = queuedResponses.shift();
    if (next instanceof Error) throw next;
    return next;
  },
});
vm.runInContext(
  `${errorClass[0]}\n${terminalHelper[0]}\n${protectedFollower[0]}\n${publicFollower[0]}\nthis.operationTerminalError = operationTerminalError;\nthis.followOperation = followOperation;\nthis.followPublicOperation = followPublicOperation;`,
  context,
);
const terminalError = context.operationTerminalError;

assert.equal(terminalError({ status: "succeeded" }), null);

const stringFailure = terminalError({
  status: "failed",
  error: "hypervisor operation failed: VM 'test' was not found",
});
assert.equal(stringFailure.message, "hypervisor operation failed: VM 'test' was not found");
assert.equal(stringFailure.code, "operation_failed");
assert.equal(stringFailure.status, 400);

const structuredFailure = terminalError({
  status: "failed",
  error: { message: "disk allocation failed", code: "disk_full", request_id: "req-42" },
});
assert.equal(structuredFailure.message, "disk allocation failed");
assert.equal(structuredFailure.code, "disk_full");
assert.equal(structuredFailure.requestId, "req-42");

const cancelled = terminalError({ status: "cancelled", error: null });
assert.equal(cancelled.message, "Operation was cancelled");
assert.equal(cancelled.code, "operation_cancelled");
assert.equal(cancelled.status, 409);

const emptyFailure = terminalError({ status: "failed", error: "" });
assert.equal(emptyFailure.message, "Operation failed");

async function runFollowerTests() {
  apiCalls = 0;
  await assert.rejects(
    context.followOperation({ operation: { id: "job-1", status: "failed", error: "define failed" } }),
    (error) => error.message === "define failed",
  );
  assert.equal(apiCalls, 0, "an already-terminal operation must not be polled");

  await assert.rejects(
    context.followOperation({
      id: "cd85423e-da8e-4190-a08b-151c41e9bbad",
      kind: "vm.delete",
      status: "failed",
      error: "database delete failed",
    }),
    (error) => error.message === "database delete failed",
  );
  assert.equal(apiCalls, 0, "a direct UUID job payload must be recognized without polling");

  await assert.rejects(
    context.followOperation({ operation: { id: "job-2", status: "cancelled", error: null } }),
    (error) => error.code === "operation_cancelled",
  );

  queuedResponses.push({ operation: { id: "job-3", status: "failed", error: "VM 'test' was not found" } });
  await assert.rejects(
    context.followOperation({ operation: { id: "job-3", status: "queued" } }),
    (error) => error.message === "VM 'test' was not found",
  );

  queuedResponses.push({ operation: { id: "job-4", status: "succeeded", result: { deleted: true } } });
  const succeeded = await context.followOperation({ operation: { id: "job-4", status: "queued" } });
  assert.equal(succeeded.status, "succeeded");

  queuedResponses.push({ operation: { id: "job-5", status: "cancelled", error: null } });
  await assert.rejects(
    context.followPublicOperation({ operation: { id: "job-5", status: "queued" } }),
    (error) => error.code === "operation_cancelled",
  );

  await assert.rejects(
    context.followPublicOperation({
      id: "75047920-ed69-4401-9186-c551a7a65f3c",
      kind: "vm.reinstall",
      status: "failed",
      error: "guest password is required",
    }),
    (error) => error.message === "guest password is required",
  );

  const unavailable = new Error("missing");
  unavailable.status = 404;
  unavailable.requestId = "req-missing";
  queuedResponses.push(unavailable);
  await assert.rejects(
    context.followPublicOperation({ operation: { id: "job-6", status: "queued" } }),
    (error) => error.code === "operation_status_unavailable" && error.requestId === "req-missing",
  );
}

runFollowerTests()
  .then(() => console.log("operation failures, cancellation, polling, and success passed"))
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
