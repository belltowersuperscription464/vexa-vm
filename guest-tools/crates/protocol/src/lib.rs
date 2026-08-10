//! Authenticated, replay-resistant protocol shared by the Vexa host and guest agent.
//!
//! The transport is a length-prefixed JSON stream over a named virtio-serial channel. Every
//! request and response is authenticated with a per-VM 256-bit secret. The secret is never sent
//! over the channel.

use std::{
    collections::{HashSet, VecDeque},
    io::{Read, Write},
    net::IpAddr,
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: u64 = 120;
pub const MIN_SECRET_BYTES: usize = 32;
const REQUEST_DOMAIN: &[u8] = b"VEXA-GUEST-REQUEST-V2\0";
const RESPONSE_DOMAIN: &[u8] = b"VEXA-GUEST-RESPONSE-V2\0";
const REQUEST_ENCRYPTION_DOMAIN: &[u8] = b"VEXA-GUEST-REQUEST-ENC-V2\0";
const RESPONSE_ENCRYPTION_DOMAIN: &[u8] = b"VEXA-GUEST-RESPONSE-ENC-V2\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Ping,
    Health,
    SetPassword {
        username: String,
        password: String,
    },
    SetHostname {
        hostname: String,
    },
    SetDns {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
        servers: Vec<IpAddr>,
    },
    SetNetwork {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
        addresses: Vec<NetworkAddress>,
        #[serde(default)]
        gateways: Vec<IpAddr>,
        #[serde(default)]
        dns_servers: Vec<IpAddr>,
    },
    SetSshKeys {
        username: String,
        authorized_keys: Vec<String>,
    },
    Shutdown,
    Reboot,
}

impl Command {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Health => "health",
            Self::SetPassword { .. } => "set_password",
            Self::SetHostname { .. } => "set_hostname",
            Self::SetDns { .. } => "set_dns",
            Self::SetNetwork { .. } => "set_network",
            Self::SetSshKeys { .. } => "set_ssh_keys",
            Self::Shutdown => "shutdown",
            Self::Reboot => "reboot",
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Ping | Self::Health | Self::Shutdown | Self::Reboot => Ok(()),
            Self::SetPassword { username, password } => {
                validate_username(username)?;
                if password.is_empty() || password.len() > 1024 {
                    return Err(ProtocolError::InvalidCommand(
                        "password must contain between 1 and 1024 bytes".into(),
                    ));
                }
                if password
                    .chars()
                    .any(|character| matches!(character, '\0' | '\r' | '\n'))
                {
                    return Err(ProtocolError::InvalidCommand(
                        "password contains an unsupported control character".into(),
                    ));
                }
                Ok(())
            }
            Self::SetHostname { hostname } => validate_hostname(hostname),
            Self::SetDns { interface, servers } => {
                if let Some(interface) = interface {
                    if interface.is_empty()
                        || interface.len() > 128
                        || interface.chars().any(char::is_control)
                    {
                        return Err(ProtocolError::InvalidCommand("interface name is invalid".into()));
                    }
                }
                if servers.is_empty() || servers.len() > 8 {
                    return Err(ProtocolError::InvalidCommand(
                        "between 1 and 8 DNS servers are required".into(),
                    ));
                }
                if servers.iter().any(IpAddr::is_unspecified) {
                    return Err(ProtocolError::InvalidCommand(
                        "unspecified DNS addresses are not accepted".into(),
                    ));
                }
                Ok(())
            }
            Self::SetNetwork {
                interface,
                addresses,
                gateways,
                dns_servers,
            } => {
                validate_interface(interface.as_deref())?;
                if addresses.len() > 64 {
                    return Err(ProtocolError::InvalidCommand(
                        "at most 64 network addresses are accepted".into(),
                    ));
                }
                let mut unique = HashSet::new();
                for item in addresses {
                    let maximum = if item.address.is_ipv4() { 32 } else { 128 };
                    if item.prefix_length > maximum
                        || item.address.is_unspecified()
                        || item.address.is_loopback()
                        || item.address.is_multicast()
                        || !unique.insert((item.address, item.prefix_length))
                    {
                        return Err(ProtocolError::InvalidCommand(
                            "network address or prefix is invalid or duplicated".into(),
                        ));
                    }
                }
                if gateways.len() > 2 || dns_servers.len() > 8 {
                    return Err(ProtocolError::InvalidCommand(
                        "at most one gateway per family and 8 DNS servers are accepted".into(),
                    ));
                }
                let mut gateway_families = HashSet::new();
                for gateway in gateways {
                    if gateway.is_unspecified()
                        || gateway.is_loopback()
                        || gateway.is_multicast()
                        || !gateway_families.insert(gateway.is_ipv4())
                    {
                        return Err(ProtocolError::InvalidCommand(
                            "gateway is invalid or duplicated for its address family".into(),
                        ));
                    }
                }
                if dns_servers.iter().any(|address| {
                    address.is_unspecified() || address.is_loopback() || address.is_multicast()
                }) {
                    return Err(ProtocolError::InvalidCommand("DNS address is invalid".into()));
                }
                Ok(())
            }
            Self::SetSshKeys {
                username,
                authorized_keys,
            } => {
                validate_username(username)?;
                if authorized_keys.len() > 64 {
                    return Err(ProtocolError::InvalidCommand(
                        "at most 64 SSH keys may be installed".into(),
                    ));
                }
                for key in authorized_keys {
                    validate_ssh_key(key)?;
                }
                Ok(())
            }
        }
    }
}

fn validate_interface(interface: Option<&str>) -> Result<(), ProtocolError> {
    if let Some(interface) = interface {
        if interface.is_empty() || interface.len() > 128 || interface.chars().any(char::is_control) {
            return Err(ProtocolError::InvalidCommand("interface name is invalid".into()));
        }
    }
    Ok(())
}

impl std::fmt::Debug for Command {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Command")
            .field("action", &self.kind())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub request_id: String,
    pub sent_at: i64,
    pub nonce: String,
    /// AES-256-GCM encrypted serialized [`Command`]. The channel transport is
    /// local but not assumed confidential; credentials must never cross it in
    /// plaintext even if another local process substitutes the Unix socket.
    pub encrypted_command: String,
    pub signature: String,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Request")
            .field("version", &self.version)
            .field("request_id", &self.request_id)
            .field("sent_at", &self.sent_at)
            .field("encrypted_command", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct UnsignedRequest<'a> {
    version: u16,
    request_id: &'a str,
    sent_at: i64,
    nonce: &'a str,
    encrypted_command: &'a str,
}

#[derive(Serialize)]
struct RequestAad<'a> {
    version: u16,
    request_id: &'a str,
    sent_at: i64,
    nonce: &'a str,
}

impl Request {
    pub fn signed(
        request_id: impl Into<String>,
        sent_at: i64,
        nonce: impl Into<String>,
        command: Command,
        secret: &[u8],
    ) -> Result<Self, ProtocolError> {
        require_strong_secret(secret)?;
        command.validate()?;
        let mut request = Self {
            version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            sent_at,
            nonce: nonce.into(),
            encrypted_command: String::new(),
            signature: String::new(),
        };
        request.validate_envelope()?;
        request.encrypted_command = encrypt_json(
            REQUEST_ENCRYPTION_DOMAIN,
            &request.nonce,
            &request.aad(),
            &command,
            secret,
        )?;
        validate_ciphertext(&request.encrypted_command, "request")?;
        request.signature = sign_json(REQUEST_DOMAIN, &request.unsigned(), secret)?;
        Ok(request)
    }

    /// Authenticate, reject replays, decrypt, and validate the closed command
    /// enum. No command bytes are exposed before authentication succeeds.
    pub fn verify_and_decrypt(
        &self,
        secret: &[u8],
        now: i64,
        max_clock_skew_seconds: u64,
        replay_cache: &mut ReplayCache,
    ) -> Result<Command, ProtocolError> {
        require_strong_secret(secret)?;
        self.validate_envelope()?;
        validate_ciphertext(&self.encrypted_command, "request")?;
        let skew = self.sent_at.abs_diff(now);
        if skew > max_clock_skew_seconds {
            return Err(ProtocolError::Expired);
        }
        verify_json(REQUEST_DOMAIN, &self.unsigned(), secret, &self.signature)?;
        replay_cache.accept(&self.request_id, &self.nonce, now, max_clock_skew_seconds)?;
        let command: Command = decrypt_json(
            REQUEST_ENCRYPTION_DOMAIN,
            &self.nonce,
            &self.aad(),
            &self.encrypted_command,
            secret,
        )?;
        command.validate()?;
        Ok(command)
    }

    fn unsigned(&self) -> UnsignedRequest<'_> {
        UnsignedRequest {
            version: self.version,
            request_id: &self.request_id,
            sent_at: self.sent_at,
            nonce: &self.nonce,
            encrypted_command: &self.encrypted_command,
        }
    }

    fn aad(&self) -> RequestAad<'_> {
        RequestAad {
            version: self.version,
            request_id: &self.request_id,
            sent_at: self.sent_at,
            nonce: &self.nonce,
        }
    }

    fn validate_envelope(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProtocolError::InvalidEnvelope("invalid request_id".into()));
        }
        let nonce = STANDARD_NO_PAD
            .decode(&self.nonce)
            .map_err(|_| ProtocolError::InvalidEnvelope("nonce is not base64".into()))?;
        if !(16..=64).contains(&nonce.len()) {
            return Err(ProtocolError::InvalidEnvelope(
                "nonce must decode to 16 through 64 bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseData {
    Pong {
        agent_version: String,
    },
    Health {
        agent_version: String,
        operating_system: String,
        hostname: String,
        uptime_seconds: u64,
        capabilities: Vec<String>,
    },
    Action {
        changed: bool,
        reboot_required: bool,
        message: String,
    },
}

impl ResponseData {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Pong { agent_version } => validate_response_text("agent version", agent_version, 64, false),
            Self::Health {
                agent_version,
                operating_system,
                hostname,
                capabilities,
                ..
            } => {
                validate_response_text("agent version", agent_version, 64, false)?;
                validate_response_text("operating system", operating_system, 256, false)?;
                validate_response_text("reported hostname", hostname, 253, false)?;
                if capabilities.len() > 64 {
                    return Err(ProtocolError::InvalidEnvelope(
                        "too many reported capabilities".into(),
                    ));
                }
                for capability in capabilities {
                    validate_response_text("capability", capability, 64, false)?;
                }
                Ok(())
            }
            Self::Action { message, .. } => validate_response_text("action message", message, 1024, true),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.code.is_empty()
            || self.code.len() > 64
            || !self.code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
            })
        {
            return Err(ProtocolError::InvalidEnvelope(
                "response error code is invalid".into(),
            ));
        }
        validate_response_text("response error message", &self.message, 1024, true)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub request_id: String,
    pub sent_at: i64,
    pub request_nonce: String,
    pub ok: bool,
    /// AES-256-GCM encrypted response data or error body.
    pub encrypted_payload: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedResponse<'a> {
    version: u16,
    request_id: &'a str,
    sent_at: i64,
    request_nonce: &'a str,
    ok: bool,
    encrypted_payload: &'a str,
}

#[derive(Serialize)]
struct ResponseAad<'a> {
    version: u16,
    request_id: &'a str,
    sent_at: i64,
    request_nonce: &'a str,
    ok: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponsePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<ResponseData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResponse {
    pub data: Option<ResponseData>,
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn success(
        request: &Request,
        sent_at: i64,
        data: ResponseData,
        secret: &[u8],
    ) -> Result<Self, ProtocolError> {
        Self::signed(request, sent_at, true, Some(data), None, secret)
    }

    pub fn failure(
        request: &Request,
        sent_at: i64,
        code: impl Into<String>,
        message: impl Into<String>,
        secret: &[u8],
    ) -> Result<Self, ProtocolError> {
        Self::signed(
            request,
            sent_at,
            false,
            None,
            Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
            secret,
        )
    }

    pub fn verify_and_decrypt(
        &self,
        secret: &[u8],
        expected_request_id: &str,
        expected_nonce: &str,
        expected_command: &Command,
        request_sent_at: i64,
        now: i64,
        max_clock_skew_seconds: u64,
    ) -> Result<VerifiedResponse, ProtocolError> {
        require_strong_secret(secret)?;
        if self.version != PROTOCOL_VERSION
            || self.request_id != expected_request_id
            || self.request_nonce != expected_nonce
            || self.sent_at < request_sent_at
            || self.sent_at.abs_diff(now) > max_clock_skew_seconds
        {
            return Err(ProtocolError::InvalidEnvelope(
                "response does not match the request".into(),
            ));
        }
        validate_ciphertext(&self.encrypted_payload, "response")?;
        verify_json(RESPONSE_DOMAIN, &self.unsigned(), secret, &self.signature)?;
        let payload: ResponsePayload = decrypt_json(
            RESPONSE_ENCRYPTION_DOMAIN,
            &self.request_nonce,
            &self.aad(),
            &self.encrypted_payload,
            secret,
        )?;
        if self.ok == payload.error.is_some() || self.ok != payload.data.is_some() {
            return Err(ProtocolError::InvalidEnvelope(
                "response result is inconsistent".into(),
            ));
        }
        if let Some(data) = payload.data.as_ref() {
            data.validate()?;
        }
        if let Some(error) = payload.error.as_ref() {
            error.validate()?;
        }
        if let Some(data) = payload.data.as_ref() {
            let matches_command = matches!(
                (expected_command, data),
                (Command::Ping, ResponseData::Pong { .. })
                    | (Command::Health, ResponseData::Health { .. })
                    | (
                        Command::SetPassword { .. }
                            | Command::SetHostname { .. }
                            | Command::SetDns { .. }
                            | Command::SetNetwork { .. }
                            | Command::SetSshKeys { .. }
                            | Command::Shutdown
                            | Command::Reboot,
                        ResponseData::Action { .. }
                    )
            );
            if !matches_command {
                return Err(ProtocolError::InvalidEnvelope(
                    "response type does not match the request command".into(),
                ));
            }
        }
        Ok(VerifiedResponse {
            data: payload.data,
            error: payload.error,
        })
    }

    fn signed(
        request: &Request,
        sent_at: i64,
        ok: bool,
        data: Option<ResponseData>,
        error: Option<ErrorBody>,
        secret: &[u8],
    ) -> Result<Self, ProtocolError> {
        require_strong_secret(secret)?;
        if ok == error.is_some() || ok != data.is_some() {
            return Err(ProtocolError::InvalidEnvelope(
                "response result is inconsistent".into(),
            ));
        }
        if let Some(data) = data.as_ref() {
            data.validate()?;
        }
        if let Some(error) = error.as_ref() {
            error.validate()?;
        }
        let mut response = Self {
            version: PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            sent_at,
            request_nonce: request.nonce.clone(),
            ok,
            encrypted_payload: String::new(),
            signature: String::new(),
        };
        response.encrypted_payload = encrypt_json(
            RESPONSE_ENCRYPTION_DOMAIN,
            &response.request_nonce,
            &response.aad(),
            &ResponsePayload { data, error },
            secret,
        )?;
        response.signature = sign_json(RESPONSE_DOMAIN, &response.unsigned(), secret)?;
        Ok(response)
    }

    fn unsigned(&self) -> UnsignedResponse<'_> {
        UnsignedResponse {
            version: self.version,
            request_id: &self.request_id,
            sent_at: self.sent_at,
            request_nonce: &self.request_nonce,
            ok: self.ok,
            encrypted_payload: &self.encrypted_payload,
        }
    }

    fn aad(&self) -> ResponseAad<'_> {
        ResponseAad {
            version: self.version,
            request_id: &self.request_id,
            sent_at: self.sent_at,
            request_nonce: &self.request_nonce,
            ok: self.ok,
        }
    }
}

pub struct ReplayCache {
    capacity: usize,
    seen: HashSet<String>,
    order: VecDeque<(i64, String)>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn accept(
        &mut self,
        request_id: &str,
        nonce: &str,
        now: i64,
        max_age_seconds: u64,
    ) -> Result<(), ProtocolError> {
        while let Some((timestamp, key)) = self.order.front() {
            let maximum_age = max_age_seconds.min(i64::MAX as u64) as i64;
            if timestamp.saturating_add(maximum_age) >= now && self.order.len() < self.capacity {
                break;
            }
            self.seen.remove(key);
            self.order.pop_front();
        }

        let key = format!("{request_id}:{nonce}");
        if !self.seen.insert(key.clone()) {
            return Err(ProtocolError::Replay);
        }
        self.order.push_back((now, key));
        Ok(())
    }
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, ProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(length));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn encrypt_json<A: Serialize, T: Serialize>(
    domain: &[u8],
    encoded_nonce: &str,
    aad: &A,
    value: &T,
    secret: &[u8],
) -> Result<String, ProtocolError> {
    require_strong_secret(secret)?;
    let (mut key, nonce) = encryption_material(domain, encoded_nonce, secret)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtocolError::Encryption)?;
    let associated_data = associated_data(domain, aad)?;
    let mut plaintext = serde_json::to_vec(value)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| ProtocolError::Encryption);
    plaintext.fill(0);
    key.fill(0);
    Ok(STANDARD_NO_PAD.encode(encrypted?))
}

fn decrypt_json<A: Serialize, T: DeserializeOwned>(
    domain: &[u8],
    encoded_nonce: &str,
    aad: &A,
    encoded_ciphertext: &str,
    secret: &[u8],
) -> Result<T, ProtocolError> {
    require_strong_secret(secret)?;
    let ciphertext = STANDARD_NO_PAD
        .decode(encoded_ciphertext)
        .or_else(|_| STANDARD.decode(encoded_ciphertext))
        .map_err(|_| ProtocolError::InvalidEnvelope("ciphertext is not base64".into()))?;
    let (mut key, nonce) = encryption_material(domain, encoded_nonce, secret)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtocolError::Authentication)?;
    let associated_data = associated_data(domain, aad)?;
    let decrypted = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| ProtocolError::Authentication);
    key.fill(0);
    let mut plaintext = decrypted?;
    let result = serde_json::from_slice(&plaintext);
    plaintext.fill(0);
    Ok(result?)
}

fn encryption_material(
    domain: &[u8],
    encoded_nonce: &str,
    secret: &[u8],
) -> Result<([u8; 32], [u8; 12]), ProtocolError> {
    let decoded_nonce = STANDARD_NO_PAD
        .decode(encoded_nonce)
        .map_err(|_| ProtocolError::InvalidEnvelope("nonce is not base64".into()))?;
    if !(16..=64).contains(&decoded_nonce.len()) {
        return Err(ProtocolError::InvalidEnvelope(
            "nonce must decode to 16 through 64 bytes".into(),
        ));
    }
    let mut key_mac = <HmacSha256 as Mac>::new_from_slice(secret).map_err(|_| ProtocolError::WeakSecret)?;
    key_mac.update(domain);
    key_mac.update(b"key");
    let derived = key_mac.finalize().into_bytes();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&derived);

    let mut nonce_hash = Sha256::new();
    nonce_hash.update(domain);
    nonce_hash.update(b"nonce");
    nonce_hash.update(&decoded_nonce);
    let digest = nonce_hash.finalize();
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    Ok((key, nonce))
}

fn associated_data<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, ProtocolError> {
    let encoded = serde_json::to_vec(value)?;
    let mut result = Vec::with_capacity(domain.len() + encoded.len());
    result.extend_from_slice(domain);
    result.extend_from_slice(&encoded);
    Ok(result)
}

fn validate_ciphertext(value: &str, label: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_FRAME_BYTES * 2 {
        return Err(ProtocolError::InvalidEnvelope(format!(
            "{label} ciphertext has an invalid size"
        )));
    }
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| ProtocolError::InvalidEnvelope(format!("{label} ciphertext is not base64")))?;
    if decoded.len() < 16 || decoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidEnvelope(format!(
            "{label} ciphertext has an invalid size"
        )));
    }
    Ok(())
}

fn sign_json<T: Serialize>(domain: &[u8], value: &T, secret: &[u8]) -> Result<String, ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).map_err(|_| ProtocolError::WeakSecret)?;
    mac.update(domain);
    mac.update(&payload);
    Ok(STANDARD_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_json<T: Serialize>(
    domain: &[u8],
    value: &T,
    secret: &[u8],
    signature: &str,
) -> Result<(), ProtocolError> {
    let signature = STANDARD_NO_PAD
        .decode(signature)
        .map_err(|_| ProtocolError::Authentication)?;
    let payload = serde_json::to_vec(value)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).map_err(|_| ProtocolError::WeakSecret)?;
    mac.update(domain);
    mac.update(&payload);
    mac.verify_slice(&signature)
        .map_err(|_| ProtocolError::Authentication)
}

fn require_strong_secret(secret: &[u8]) -> Result<(), ProtocolError> {
    if secret.len() < MIN_SECRET_BYTES {
        Err(ProtocolError::WeakSecret)
    } else {
        Ok(())
    }
}

fn validate_username(username: &str) -> Result<(), ProtocolError> {
    if username.is_empty()
        || username.len() > 64
        || username.starts_with('-')
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidCommand(
            "only a local username may be used".into(),
        ));
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<(), ProtocolError> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(ProtocolError::InvalidCommand("hostname is invalid".into()));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProtocolError::InvalidCommand("hostname is invalid".into()));
        }
    }
    Ok(())
}

fn validate_ssh_key(key: &str) -> Result<(), ProtocolError> {
    if key.is_empty()
        || key.len() > 16 * 1024
        || key
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(ProtocolError::InvalidCommand("SSH key is invalid".into()));
    }
    let mut parts = key.split_whitespace();
    let kind = parts.next().unwrap_or_default();
    let encoded = parts.next().unwrap_or_default();
    let supported = kind == "ssh-ed25519"
        || kind == "ssh-rsa"
        || kind.starts_with("ecdsa-sha2-")
        || kind.starts_with("sk-ssh-")
        || kind.starts_with("sk-ecdsa-");
    if !supported
        || encoded.len() > 12 * 1024
        || (STANDARD_NO_PAD.decode(encoded).is_err() && STANDARD.decode(encoded).is_err())
    {
        return Err(ProtocolError::InvalidCommand(
            "SSH key type or encoding is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_response_text(
    label: &str,
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidEnvelope(format!("{label} is invalid")));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol secret must contain at least 32 bytes")]
    WeakSecret,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("authentication failed")]
    Authentication,
    #[error("encryption failed")]
    Encryption,
    #[error("request timestamp is outside the allowed window")]
    Expired,
    #[error("request was already accepted")]
    Replay,
    #[error("frame has an invalid size: {0} bytes")]
    FrameTooLarge(usize),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";

    #[test]
    fn signed_request_round_trip_and_replay_rejection() {
        let request =
            Request::signed("req-1", 1_700_000_000, NONCE, Command::Ping, SECRET).expect("sign request");
        let mut cache = ReplayCache::new(16);
        let command = request
            .verify_and_decrypt(SECRET, 1_700_000_010, 120, &mut cache)
            .expect("verify request");
        assert!(matches!(command, Command::Ping));
        assert!(matches!(
            request.verify_and_decrypt(SECRET, 1_700_000_010, 120, &mut cache),
            Err(ProtocolError::Replay)
        ));
    }

    #[test]
    fn tampering_is_rejected() {
        let mut request =
            Request::signed("req-2", 1_700_000_000, NONCE, Command::Ping, SECRET).expect("sign request");
        let replacement = if request.encrypted_command.starts_with('A') {
            "B"
        } else {
            "A"
        };
        request.encrypted_command.replace_range(0..1, replacement);
        assert!(matches!(
            request.verify_and_decrypt(SECRET, 1_700_000_010, 120, &mut ReplayCache::new(16)),
            Err(ProtocolError::Authentication)
        ));
    }

    #[test]
    fn response_is_bound_to_request_and_nonce() {
        let request =
            Request::signed("req-3", 1_700_000_000, NONCE, Command::Health, SECRET).expect("sign request");
        let response = Response::success(
            &request,
            1_700_000_001,
            ResponseData::Health {
                agent_version: "0.1.0".into(),
                operating_system: "Test OS".into(),
                hostname: "guest-1".into(),
                uptime_seconds: 42,
                capabilities: vec!["health".into()],
            },
            SECRET,
        )
        .expect("sign response");
        response
            .verify_and_decrypt(
                SECRET,
                "req-3",
                NONCE,
                &Command::Health,
                1_700_000_000,
                1_700_000_010,
                120,
            )
            .expect("verify response");
        assert!(response
            .verify_and_decrypt(
                SECRET,
                "another",
                NONCE,
                &Command::Health,
                1_700_000_000,
                1_700_000_010,
                120,
            )
            .is_err());
    }

    #[test]
    fn sensitive_command_values_are_not_serialized_in_plaintext() {
        let password = "DoNotExpose-Password-2026";
        let request = Request::signed(
            "req-secret",
            1_700_000_000,
            NONCE,
            Command::SetPassword {
                username: "root".into(),
                password: password.into(),
            },
            SECRET,
        )
        .expect("encrypt request");
        let wire = serde_json::to_string(&request).expect("serialize request");
        assert!(!wire.contains(password));
        assert!(!wire.contains("set_password"));
        let decrypted = request
            .verify_and_decrypt(SECRET, 1_700_000_001, 120, &mut ReplayCache::new(16))
            .expect("decrypt request");
        assert!(matches!(
            decrypted,
            Command::SetPassword { password: value, .. } if value == password
        ));
    }

    #[test]
    fn response_type_and_freshness_are_bound_to_the_request() {
        let request =
            Request::signed("req-kind", 1_700_000_000, NONCE, Command::Health, SECRET).expect("sign request");
        let response = Response::success(
            &request,
            1_700_000_001,
            ResponseData::Pong {
                agent_version: "0.1.0".into(),
            },
            SECRET,
        )
        .expect("sign response");
        assert!(response
            .verify_and_decrypt(
                SECRET,
                "req-kind",
                NONCE,
                &Command::Health,
                1_700_000_000,
                1_700_000_010,
                120,
            )
            .is_err());
        assert!(response
            .verify_and_decrypt(
                SECRET,
                "req-kind",
                NONCE,
                &Command::Ping,
                1_700_000_000,
                1_700_001_000,
                120,
            )
            .is_err());
    }

    #[test]
    fn frame_reader_rejects_oversized_payload_before_allocation() {
        let bytes = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        let error = read_frame::<_, Request>(&mut bytes.as_slice()).expect_err("oversized frame");
        assert!(matches!(error, ProtocolError::FrameTooLarge(_)));
    }

    #[test]
    fn response_payloads_are_bounded_before_signing_or_acceptance() {
        let request =
            Request::signed("req-bounds", 1_700_000_000, NONCE, Command::Ping, SECRET).expect("sign request");
        assert!(Response::success(
            &request,
            1_700_000_001,
            ResponseData::Pong {
                agent_version: "x".repeat(65),
            },
            SECRET,
        )
        .is_err());
        assert!(Response::failure(&request, 1_700_000_001, "INVALID CODE", "failure", SECRET,).is_err());
    }

    #[test]
    fn command_validation_rejects_key_options_and_unsafe_names() {
        let with_options = Command::SetSshKeys {
            username: "root".into(),
            authorized_keys: vec!["command=whoami ssh-ed25519 AAAA".into()],
        };
        assert!(with_options.validate().is_err());
        let unsafe_user = Command::SetPassword {
            username: "../root".into(),
            password: "secret".into(),
        };
        assert!(unsafe_user.validate().is_err());
    }
}
