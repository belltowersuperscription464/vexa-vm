# Guest Tools protocol v2

The host and guest communicate over one named virtio-serial channel. There is no guest TCP/UDP
listener. Each frame is a four-byte unsigned big-endian length followed by UTF-8 JSON. Empty frames
and frames over 65,536 bytes are rejected before allocation.

## Authenticated encryption

Each VM has an independent cryptographically random secret containing at least 256 bits. A request
contains `version`, `request_id`, Unix `sent_at`, a base64 random `nonce`, a base64
`encrypted_command`, and a base64 HMAC-SHA-256 `signature`. The command is a closed tagged enum
serialized as JSON and encrypted with AES-256-GCM. Direction-separated keys are derived from the
per-VM secret; direction/version domains and the envelope fields are authenticated as additional
data. The outer HMAC covers the versioned request domain and every field except the signature,
including the ciphertext. Hosts must use the `vexa-guest-protocol` crate to avoid alternate
serialization or key-derivation implementations.

Responses use the same construction with a separate response key/domain. Their success data or
error body is carried only in `encrypted_payload`; the clear envelope binds it to the request ID,
request nonce, result flag and response time. The host rejects a response sent before its request,
outside the allowed clock window, or whose decrypted response variant does not match the command.
Decrypted agent versions, OS/hostname labels, capability lists, action messages, and error bodies
also have strict item/count/byte bounds before they may reach database status, API output, or logs.
There is no v1 downgrade path.

The guest accepts a request only when:

- protocol version is exactly `2`;
- the outer signature is valid under the VM's secret;
- the timestamp is within the configured 30–600 second window (120 seconds by default);
- the request-ID/nonce pair is absent from the bounded replay cache;
- AES-256-GCM authentication and decryption succeeds; and
- the command passes strict field validation.

The guest authenticates the envelope before accepting a replay-cache entry and exposing decrypted
command bytes. Authentication errors close the channel without executing an action. Passwords,
command arguments and response bodies do not cross the virtio channel as plaintext. Password values
and private keys are never returned. The protocol accepts only **public** OpenSSH keys.

## Commands

| Action | Required fields | Result |
| --- | --- | --- |
| `ping` | none | agent version |
| `health` | none | OS, hostname, OS uptime and currently enabled/available capabilities |
| `set_password` | local `username`, `password` | local password changed |
| `set_hostname` | DNS-compatible `hostname` | hostname changed |
| `set_dns` | optional interface, 1–8 IPv4/IPv6 addresses | DNS policy changed |
| `set_ssh_keys` | local username, up to 64 public keys | managed key block replaced |
| `shutdown` | none | response is flushed, then poweroff begins |
| `reboot` | none | response is flushed, then reboot begins |

Commands are intentionally not extensible through arbitrary executables or scripts. Add new commands
as reviewed enum variants with platform implementations, validation, tests, audit naming and a
protocol-version compatibility plan.
