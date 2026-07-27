# High-Performance Microservice Multiplex Protocol (HMMP)

**Complete Specification — Version 07**

| | |
|---|---|
| **Document Status** | Independent Technical Specification |
| **Version** | v07 (consolidated) |
| **Date** | July 2026 |
| **Editor** | Qingsong Wang, Advanced AI Partner |
| **License** | Apache License, Version 2.0 |

---

> **Disclaimer**: This document is an independent technical specification for the
> HMMP protocol. It is NOT an IETF Internet-Draft and has NOT been submitted to
> the IETF for standardization. The document adopts RFC-style formatting
> conventions for readability only.
>
> Copyright (c) 2026 Qingsong Wang. All rights reserved.
> Licensed under the Apache License, Version 2.0.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Architecture and Framing](#2-protocol-architecture-and-framing)
3. [Complete OpCode Map](#3-complete-opcode-map)
4. [Connection Lifecycle and Handshaking](#4-connection-lifecycle-and-handshaking)
5. [Handshake Security: Anti-Replay Nonce](#5-handshake-security-anti-replay-nonce)
6. [Naming and Discovery](#6-naming-and-discovery)
7. [Configuration Management](#7-configuration-management)
8. [Governance Extension](#8-governance-extension)
9. [Cluster Specifications](#9-cluster-specifications)
10. [Management Plane: Tenant Lifecycle](#10-management-plane-tenant-lifecycle)
11. [Management Plane: Credential Lifecycle](#11-management-plane-credential-lifecycle)
12. [Multi-Tenant Isolation Matrix](#12-multi-tenant-isolation-matrix)
13. [Security Considerations](#13-security-considerations)
14. [Implementation Errata (v07)](#14-implementation-errata-v07)
15. [References](#15-references)

---

## 1. Introduction

Modern microservice architectures require robust sub-systems for service
discovery (Naming) and configuration distribution (Config). Legacy systems
typically deploy fragmented HTTP/1.1 or multiple gRPC channels, leading to
firewall traversal issues ("Port Hell") and excessive resource footprints.

HMMP mitigates these inefficiencies by enforcing structural multiplexing over a
single long-lived TCP connection, utilizing binary frame segmentation, static
command mapping, multi-tenant strict logic boundaries, and localized
cryptographic handshakes. Version 07 extends the cable-level precision of v06
by adding:

- A Governance Extension Block (TLV-based governance metadata)
- Native wire-level circuit breaking semantics
- Floating IP orchestration for both CP and AP modes
- Graceful instance de-registration signaling
- Cluster Floating IP binding and AP-mode peer FIP preemption
- Distributed outlier voting
- Two-phase graceful shutdown mechanics
- Handshake anti-replay nonce extension
- Service metadata registration and filtered discovery
- Encrypted config transport (AES-256-GCM) and canary release
- Explicit tenant and credential lifecycle management

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

---

## 2. Protocol Architecture and Framing

HMMP is stream-oriented. All exchanges are mapped into discrete Units called
Frames. Every Frame MUST consist of a fixed 16-byte Header, followed by a
variable-length Payload.

### 2.1. Fixed Header Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic Number         |    Version    |     Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Stream ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Length                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Padding                            |
+---------------------------------------------------------------+
```

**Magic Number**: 16 bits
: MUST be fixed to 0x2026. Packets failing to match this constant SHALL be
  dropped immediately, and the underlying TCP connection MUST be terminated.

**Version**: 8 bits
: Indicates the protocol iteration. Current compliance version is 0x07.

**Flags**: 8 bits
: Bitmask representing frame properties and line-level control indicators:

| Bit | Flag | Meaning |
|-----|------|---------|
| 0x01 | Request | 1 = Request, 0 = Response |
| 0x02 | Compression | 1 = Zstd compressed payload |
| 0x04 | B - Backpressure | Cluster backpressure; client SDK MUST apply proportional local request delays |
| 0x08 | R - Redirect | Node redirect; recipient MUST migrate TCP connection to specified target |
| 0x10 | E - Encrypted | Body area uses Encrypted Body Layout (config OpCodes only) |
| 0x40 | P - Probing | Half-open circuit breaker probe stream; server MUST process even under load shedding |
| 0x80 | G - Governance | Governance Extension Block (TLV array) follows the fixed header before Payload |

Bits 4 (0x10) is allocated for FLAG_ENCRYPTED (Section 7.2). Bits 5 is
reserved for future extensions.

**Stream ID**: 32 bits
: An unsigned integer identifying the concurrent logical channel. Clients MUST
  increment this value for distinct requests. Servers MUST replicate the Stream
  ID in corresponding responses. Stream ID 0x00000000 is strictly reserved for
  Server-Initiated Asynchronous Push Notifications (Notifies).

**Payload Length**: 32 bits
: Unsigned integer stating the precise size of the variable Payload field in
  octets. Maximum length is 4,294,967,295 octets.

**Padding**: 32 bits
: Reserved for 64-bit alignment boundaries. MUST be set to 0x00000000.

### 2.2. Two-Tier Payload Structure

To maintain long-term backward compatibility, the Payload segment utilizes an
isolated Two-Tier model:

```
+-------------------+---------------------+-------------------------+
|  Metadata Length  |    Metadata Area    |        Body Area        |
|     (2 Bytes)     |   (MessagePack)     |   (Bincode / Binary)    |
+-------------------+---------------------+-------------------------+
```

**Metadata Length**: 16 bits
: Defines the boundaries of the generic transport properties block.

**Metadata Area**: Variable
: Serialized via MessagePack. Contains context keys including `trace_id`,
  `token`, `client_version`, and `body_type`. `body_type` dictates the semantic
  interpretation of the subsequent Body Area.

**Body Area**: Variable
: The core business payload. Serialized using high-density Bincode or raw
  binary blocks, mapping directly to deterministic data structures.

---

## 3. Complete OpCode Map

HMMP operations are strictly bound to numeric Command IDs passed within the
Metadata block (`body_type`). Opcodes falling within 0x0300-0x03FF are
restricted exclusively to Cluster Server Nodes. Opcodes within 0x0400-0x04FF
are restricted to Management Plane (admin_console connections).

### 3.1. Connection Lifecycle (0x0001–0x00FF)

| OpCode | Command Name | Direction |
|--------|-------------|-----------|
| 0x0001 | HandshakeRequest | Client → Server |
| 0x0002 | HandshakeResponse | Server → Client |
| 0x0003 | HeartbeatPing | Client → Server |
| 0x0004 | HeartbeatPong | Server → Client |
| 0x0005 | ClusterNodeRedirectNotify | Server → Client |
| 0x0006 | InstanceShutdownPrepareNotice | Server → Client |
| 0x0007 | NonceChallengeRequest | Client → Server |
| 0x0008 | NonceChallengeResponse | Server → Client |

### 3.2. Naming & Discovery (0x0100–0x01FF)

| OpCode | Command Name | Direction |
|--------|-------------|-----------|
| 0x0101 | RegisterInstanceRequest | Client → Server |
| 0x0103 | DeregisterInstanceRequest | Client → Server |
| 0x0105 | DiscoverServiceRequest | Client → Server |
| 0x0106 | DiscoverServiceResponse | Server → Client |
| 0x0108 | ServiceChangedNotify | Server → Client |
| 0x0109 | RegisterInstanceWithMetaRequest | Client → Server |
| 0x010A | RegisterInstanceWithMetaResponse | Server → Client |
| 0x010B | DiscoverServiceByFilterRequest | Client → Server |
| 0x010C | DiscoverServiceByFilterResponse | Server → Client |

### 3.3. Configuration Management (0x0200–0x02FF)

| OpCode | Command Name | Direction |
|--------|-------------|-----------|
| 0x0201 | GetConfigRequest | Client → Server |
| 0x0202 | ConfigResponse | Server → Client |
| 0x0203 | ListenConfigRequest | Client → Server |
| 0x0204 | ConfigChangedNotify | Server → Client |
| 0x0205 | Reserved (removed, see Section 10) | — |
| 0x0206 | Reserved (removed, see Section 10) | — |

### 3.4. Cluster Control (0x0300–0x03FF)

| OpCode | Command Name | Direction |
|--------|-------------|-----------|
| 0x0301 | RaftAppendEntriesReq | Server → Server |
| 0x0302 | RaftAppendEntriesRes | Server → Server |
| 0x0303 | RaftRequestVoteReq | Server → Server |
| 0x0304 | RaftRequestVoteRes | Server → Server |
| 0x0311 | DistroSyncDataReq | Server → Server |
| 0x0312 | ClusterNodeLoadReport | Follower → Leader |
| 0x0313 | ClusterLeaderRedirectCommand | Leader → Follower |

### 3.5. Management Plane (0x0400–0x04FF)

| OpCode | Command Name | Direction |
|--------|-------------|-----------|
| 0x0411 | AdminCreateTenantReq | Console → Server |
| 0x0412 | AdminCreateTenantRes | Server → Console |
| 0x0413 | AdminUpdateTenantPolicyReq | Console → Server |
| 0x0414 | AdminUpdateTenantPolicyRes | Server → Console |
| 0x0415 | AdminDeleteTenantReq | Console → Server |
| 0x0416 | AdminDeleteTenantRes | Server → Console |
| 0x0417 | AdminGetTenantStatsReq | Console → Server |
| 0x0418 | AdminGetTenantStatsRes | Server → Console |
| 0x0419 | AdminCreateCredentialReq | Console → Server |
| 0x041A | AdminCreateCredentialRes | Server → Console |
| 0x041B | AdminUpdateCredentialReq | Console → Server |
| 0x041C | AdminUpdateCredentialRes | Server → Console |
| 0x041D | AdminDeleteCredentialReq | Console → Server |
| 0x041E | AdminDeleteCredentialRes | Server → Console |
| 0x041F | AdminListCredentialsReq | Console → Server |
| 0x0420 | AdminListCredentialsRes | Server → Console |

---

## 4. Connection Lifecycle and Handshaking

Connections MUST transition through three sequential states managed by an
internal state machine: PENDING, AUTHENTICATING, and AUTHENTICATED.

### 4.1. The Handshake Phase

Upon establishment of a TCP connection, the connection enters the PENDING state.
The client MUST submit a HandshakeRequest within 3000 milliseconds. Failure to
do so results in an automated connection teardown by the server.

The HandshakeRequest structure is defined as follows:

```rust
HandshakeRequest {
    client_id: String,       // Unique runtime instance string
    access_key: String,      // Tenant/Application identifier
    timestamp: u64,          // Milliseconds since epoch
    signature: String,       // Hex(HMAC_SHA256(Secret, client_id+ts))
    labels: Vec<(String, String)> // Infrastructure tagging
}
```

The server authenticates the credentials. If the timestamp deviates more than
300,000 milliseconds from the server clock, the handshake SHALL be rejected
with status code 1001 (Timestamp Expired).

Upon successful verification, the server transitions the state to
AUTHENTICATED, responds with HandshakeResponse containing a cryptographically
secure Session ID, and unlocks the Naming and Config sub-systems.


---

## 5. Handshake Security: Anti-Replay Nonce

The base HMMP handshake authenticates clients using an HMAC-SHA256 signature
computed over (client_id + timestamp). While HMAC provides integrity and
authenticity, the current scheme is vulnerable to replay attacks: an attacker
who captures a valid handshake frame can re-transmit it within the timestamp
drift window (currently 300 seconds) to establish unauthorized sessions.

This extension eliminates replay attacks by introducing a server-issued nonce
that is bound into the HMAC signature computation, ensuring each handshake
proof is valid for exactly one session establishment attempt.

### 5.1. Threat Model

The following attacks are addressed by this extension:

- **Passive Replay**: An eavesdropper captures a handshake frame from the wire
  and replays it to establish a new session.
- **Active MitM Relay**: An attacker intercepts a legitimate client's handshake
  and relays it to the server while blocking the original client.
- **Pre-computation**: An attacker with access to the secret key pre-computes
  valid signatures for future timestamps and replays them without needing
  real-time access to the key.

Threats NOT addressed (out of scope):
- Key compromise (requires key rotation, not protocol change)
- Denial of service via nonce exhaustion (mitigated by rate limiting at the
  transport layer)

### 5.2. Extended Handshake Flow

The handshake sequence is extended from a single request-response to a
two-phase challenge-response protocol:

```
Client                                             Server
  |                                                  |
  |  ---- NonceChallengeRequest (0x0007) --------->  |
  |       [client_id, timestamp]                     |
  |                                                  |
  |  <--- NonceChallengeResponse (0x0008) ---------  |
  |       [server_nonce(32B), nonce_ttl_ms,          |
  |        server_timestamp]                         |
  |                                                  |
  |  ---- HandshakeRequest (0x0001) [MODIFIED] --->  |
  |       [client_id, access_key, timestamp,         |
  |        server_nonce, signature_v2, labels]       |
  |                                                  |
  |  <--- HandshakeResponse (0x0002) --------------  |
  |       [session_id, status, ...]                  |
  |                                                  |
```

### 5.3. Nonce Challenge Frames

#### OpCode 0x0007: NonceChallengeRequest

| Field | Type | Description |
|-------|------|-------------|
| client_id_len | u8 | Length of client_id |
| client_id | variable | UTF-8 client identifier |
| client_timestamp | u64 | Client's current time (ms) |

The client sends this frame immediately after TCP connection establishment (or
TLS handshake completion) and BEFORE the traditional HandshakeRequest.

#### OpCode 0x0008: NonceChallengeResponse

| Field | Type | Description |
|-------|------|-------------|
| status | u16 | 0x0000=OK, else error |
| server_nonce | 32 bytes | Cryptographic nonce |
| nonce_ttl_ms | u32 | Nonce validity window (ms) |
| server_timestamp | u64 | Server's current time (ms) |

Status values:
- 0x0000 — Nonce issued successfully
- 0x0001 — Timestamp drift too large; client should sync clock
- 0x0002 — Rate limit exceeded; retry after backoff

`server_nonce`: A 256-bit (32-byte) cryptographically random value generated by
the server. This nonce is bound to the specific TCP connection and is valid for
exactly one HandshakeRequest.

`nonce_ttl_ms`: Maximum time in milliseconds between NonceChallengeResponse and
the subsequent HandshakeRequest using this nonce. Recommended value: 5000ms.
MUST NOT exceed 30000ms.

### 5.4. Modified Signature Computation

Base protocol signature:

    sig = Hex(HMAC_SHA256(secret, client_id + timestamp))

Extended protocol signature (v2):

    sig = Hex(HMAC_SHA256(secret, client_id + timestamp + server_nonce_hex))

Where `server_nonce_hex` is the lowercase hexadecimal encoding of the 32-byte
server_nonce (producing a 64-character string).

By including the server_nonce in the HMAC input, the signature becomes bound to:
1. The specific server that issued the nonce
2. The specific TCP connection (nonce is connection-scoped)
3. A narrow time window (nonce_ttl_ms)

### 5.5. Server Nonce Management

**Generation**: Servers MUST generate nonces using a cryptographically secure
random number generator (CSPRNG). The nonce MUST be exactly 32 bytes (256 bits)
with at least 128 bits of entropy. Servers MAY structure the nonce as:

    nonce = CSPRNG(16 bytes) || HMAC_SHA256(node_secret, conn_id)[0:16]

**Validity Window**: A nonce is valid until:
- nonce_ttl_ms milliseconds have elapsed, OR
- The TCP connection on which it was issued is closed, OR
- It has been consumed by a HandshakeRequest

Whichever occurs first invalidates the nonce.

**One-Time Use**: Each nonce MUST be accepted at most once. After a
HandshakeRequest arrives carrying a nonce, the server MUST mark that nonce as
consumed regardless of whether authentication succeeds or fails. If a second
HandshakeRequest arrives with the same nonce, the server MUST reject it with
status code 0x0003 (Nonce Already Consumed).

**Cluster Coordination**: In cluster mode, nonce validation is node-local. If
the client is redirected to a different node, the new node MUST either reject
the nonce and force a new challenge exchange, or use the stateless HMAC approach
where any node sharing the cluster-wide node_secret can verify the nonce. The
stateless approach is RECOMMENDED for seamless FIP migration.

### 5.6. Timestamp Drift Enforcement

1. **NonceChallengeRequest**: Server checks |client_timestamp - server_time|
   <= MAX_TIMESTAMP_DRIFT_MS (300s). If exceeded, responds with status 0x0001
   and does NOT issue a nonce.

2. **HandshakeRequest**: Server checks |request_timestamp - server_time|
   <= min(nonce_ttl_ms, MAX_TIMESTAMP_DRIFT_MS). The tighter window
   (nonce_ttl_ms, typically 5s) effectively reduces the replay window from
   300s to 5s.

### 5.7. Backward Compatibility

| Client Behavior | Server Response |
|----------------|-----------------|
| Sends 0x0007 first | Full nonce handshake (secure) |
| Sends 0x0001 directly (no nonce field) | Legacy handshake; server MAY accept or reject based on `allow_legacy_handshake` policy |
| Sends 0x0001 with nonce field present | Full nonce verification applied |

The `allow_legacy_handshake` configuration flag controls behavior:
- `true` (default during migration): Accept legacy handshakes with a WARNING log
- `false` (hardened mode): Reject with status code 0x0004 (Nonce Required)

**Extended HandshakeRequest Body Layout**:

| Field | Type | Description |
|-------|------|-------------|
| client_id_len | u8 | Length of client_id |
| client_id | variable | UTF-8 client identifier |
| access_key_len | u8 | Length of access_key |
| access_key | variable | UTF-8 access key |
| timestamp | u64 | Milliseconds since epoch |
| signature_len | u8 | Length of signature hex |
| signature | variable | HMAC-SHA256 hex string |
| nonce_present | u8 | 0x01=present, 0x00=absent |
| server_nonce | 32 bytes | (only if nonce_present=1) |
| label_count | u8 | Number of KV labels |
| labels | Array Block | Infrastructure labels |

### 5.8. New Status Codes

| Code | Name | Semantics |
|------|------|-----------|
| 0x0003 | Nonce Already Consumed | Nonce was already used |
| 0x0004 | Nonce Required | Legacy handshake rejected in hardened mode |

---

## 6. Naming and Discovery

### 6.1. Instance Lifecycle Management

An authenticated client registers a network capability via
RegisterInstanceRequest (OpCode 0x0101).

A key attribute is `ephemeral` (Boolean). If set to TRUE, the instance is
classified under Availability-priority (AP) routing. The server ties the
lifecycle of this instance to the physical TCP connection. Upon connection
severance, all associated ephemeral instances MUST be eviscerated from the
active registry within 5000 milliseconds.

If a client wishes to gracefully evict a node without interrupting the
underlying long-lived TCP connection, it MUST dispatch an explicit
DeregisterInstanceRequest (OpCode 0x0103) mapping the unique coordinate.

### 6.2. Bandwidth-Optimized Notify

When an instance mutates or undergoes an unhealthy state transition, the server
pushes updates to all subscribed channels using ServiceChangedNotify (OpCode
0x0108) with Stream ID 0x00000000.

To minimize packet overhead over saturated downlinks, the instance array omits
verbose string metadata arrays, substituting a 64-bit `metadata_hash` and a
compressed 32-bit `metrics_pack` field. Clients SHALL evaluate this hash and
bit-field to adapt local routing maps without demanding raw JSON payloads.

### 6.3. Binary Layout: RegisterInstanceRequest (0x0101)

| Field | Type | Description |
|-------|------|-------------|
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| port | u16 | Service port number |
| ephemeral | u8 | 0x01: True, 0x00: False |
| ip_address | 4 or 16 bytes | Raw octets of network IP |
| weight | f32 | IEEE 754 float value |

The `ip_address` field MUST be dynamically inferred by the reader using
`ip_type`. If `ip_type` equals 0x04, the parser SHALL read exactly 4 octets;
if 0x06, it SHALL read 16 octets.

### 6.4. Binary Layout: DeregisterInstanceRequest (0x0103)

| Field | Type | Description |
|-------|------|-------------|
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| address_family | u16 | 0x0001: IPv4, 0x0002: IPv6 |
| ip_address | 4 or 16 bytes | Raw octets of network IP |
| port | u16 | Service port number |

Servers evaluating an unknown tuple combination MUST process the eviction
idempotently and reply successful to safeguard connection pipelining.

### 6.5. Binary Layout: Snapshot Distribution (0x0106 / 0x0108)

Both DiscoverServiceResponse (0x0106) and ServiceChangedNotify (0x0108) MUST
output an identical Snapshot format within the Body Area:

| Field | Type | Description |
|-------|------|-------------|
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| topology_version | u64 | Monotonically increasing |
| instance_count | u16 | Size of subsequent array |
| instance_array | Array Block | Array of serialized items |

Each item inside `instance_array`:

| Field | Type | Description |
|-------|------|-------------|
| ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| port | u16 | Service port number |
| is_healthy | u8 | 0x01: Active, 0x00: Dead |
| ip_address | 4 or 16 bytes | Raw network address |
| weight | f32 | Current balancing weight |
| metrics_pack | u32 | Quantized bits (Section 9.5) |
| metadata_hash | u64 | Fast hash for KV labels |

### 6.6. Service Metadata Extension

The base registration frame carries only network coordinates (IP, port, weight)
and lacks the ability to attach descriptive metadata to service instances. This
extension introduces structured key-value metadata registration and
metadata-based filtering for service discovery via OpCodes 0x0109-0x010C.

#### 6.6.1. Metadata Entry Structure

Each metadata entry is a key-value pair of UTF-8 strings. Keys are
case-sensitive:

| Field | Type | Description |
|-------|------|-------------|
| meta_count | u16 | Number of KV pairs |
| meta_entries | Array Block | Sequence of KV entries |

Each entry:

| Field | Type | Description |
|-------|------|-------------|
| key_len | u8 | Length of key string |
| key | variable | UTF-8 metadata key |
| value_len | u16 | Length of value string |
| value | variable | UTF-8 metadata value |

#### 6.6.2. Reserved Well-Known Keys

| Key | Description |
|-----|-------------|
| _hmmp.region | Deployment region identifier |
| _hmmp.zone | Availability zone |
| _hmmp.version | Service version string (semver) |
| _hmmp.env | Environment (prod/staging/dev) |
| _hmmp.weight_override | Server-computed weight adjustment |
| _hmmp.canary | Canary deployment marker |
| _hmmp.protocol | Application-level protocol hint |
| _hmmp.registered_at | UTC timestamp of registration (ISO) |

Keys beginning with `_hmmp.` are reserved. Servers MUST silently ignore unknown
`_hmmp.` keys to ensure forward compatibility.

#### 6.6.3. Canonical Metadata Hash

The 64-bit `metadata_hash` is computed deterministically:

1. Sort all metadata entries by key in ascending byte-wise order
2. For each sorted entry, concatenate: `key_bytes || 0x00 || value_bytes || 0x00`
3. Compute FNV-1a 64-bit hash over the concatenated byte stream
4. An empty metadata set (meta_count=0) MUST produce hash 0x0000000000000000

```
hash = 0xcbf29ce484222325  (FNV offset basis)
for each byte b in input:
    hash = hash XOR b
    hash = hash * 0x100000001b3  (FNV prime)
```

#### 6.6.4. Constraints and Limits

| Constraint | Limit | Enforcement |
|-----------|-------|-------------|
| Max metadata entries per instance | 32 | Reject with 1400 |
| Max key length | 64 bytes | Reject with 1400 |
| Max value length | 512 bytes | Reject with 1400 |
| Max total metadata size (encoded) | 8192 bytes | Reject with 1400 |
| Max filter expression nesting depth | 8 | Reject with 1400 |
| Max filter predicates per request | 16 | Reject with 1400 |

#### 6.6.5. RegisterInstanceWithMetaRequest (0x0109)

The first seven fields are identical to base RegisterInstanceRequest (0x0101),
followed by metadata:

| Field | Type | Description |
|-------|------|-------------|
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| port | u16 | Service port number |
| ephemeral | u8 | 0x01: True, 0x00: False |
| ip_address | 4 or 16 bytes | Raw octets of network IP |
| weight | f32 | IEEE 754 float value |
| meta_count | u16 | Number of metadata KV |
| meta_entries | Array Block | Metadata KV entries |

#### 6.6.6. RegisterInstanceWithMetaResponse (0x010A)

Fixed 16 octets:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Topology Version (u64)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Metadata Hash (u64)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### 6.6.7. DiscoverServiceByFilterRequest (0x010B)

| Field | Type | Description |
|-------|------|-------------|
| tenant_len | u16 | Length of Tenant string |
| tenant | variable | UTF-8 tenant namespace |
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| filter_expr_len | u16 | Length of filter expression |
| filter_expr | variable | Encoded filter expression |
| include_metadata | u8 | 0x01: Include full meta, 0x00: Hash only |

#### 6.6.8. DiscoverServiceByFilterResponse (0x010C)

| Field | Type | Description |
|-------|------|-------------|
| svc_len | u16 | Length of Service Name |
| service_name | variable | UTF-8 encoded string |
| topology_version | u64 | Monotonically increasing |
| total_count | u16 | Instances before filter |
| instance_count | u16 | Instances after filter |
| instance_array | Array Block | Array of extended items |

Each item extends the base snapshot item with:

| Field | Type | Description |
|-------|------|-------------|
| meta_count | u16 | Number of KV pairs |
| meta_entries | Array Block | Full metadata (if include_metadata=0x01) |

### 6.7. Filter Expression Specification

The filter expression is a binary-encoded tree structure. Each node is either a
LEAF predicate or a LOGICAL combinator:

| Tag | Node Type | Payload |
|-----|-----------|---------|
| 0x01 | LEAF predicate | key + operator + operand |
| 0x02 | AND combinator | child_count + children[] |
| 0x03 | OR combinator | child_count + children[] |
| 0x04 | NOT combinator | single child node |

**Comparison Operators** (LEAF payload):

| Op | Operator | Semantics |
|----|----------|-----------|
| 0x01 | EQ | Exact string match |
| 0x02 | NE | Exact string mismatch |
| 0x03 | PREFIX | Value starts with operand |
| 0x04 | CONTAINS | Value contains operand |
| 0x05 | IN | Value in comma-separated set |
| 0x06 | EXISTS | Key exists (operand ignored) |
| 0x07 | NOT_EXISTS | Key absent (operand ignored) |
| 0x08 | REGEX | Value matches RE2 regex pattern |

**Evaluation Semantics**:
- Missing key evaluates to false for all operators except NOT_EXISTS
- Empty filter (filter_expr_len=0) matches ALL instances
- String comparison is byte-exact (case-sensitive)
- Server SHOULD short-circuit: AND stops at first false, OR at first true

### 6.8. Subscription and Change Notification

To establish a filtered subscription, the client SHOULD first issue a
DiscoverServiceByFilterRequest (0x010B), then subscribe via the base
ServiceSubscribeRequest (0x0107). The server evaluates the filter on each
topology change and only pushes ServiceChangedNotify (0x0108) if the filtered
result set differs.

When a subscriber detects a metadata_hash change, it SHOULD issue a targeted
DiscoverServiceByFilterRequest with `include_metadata=0x01` to retrieve updated
metadata content (two-phase approach: lightweight hash notification + on-demand
full metadata retrieval).

### 6.9. Cluster Propagation

In cluster mode, the canonical metadata_hash and full metadata content MUST be
propagated alongside instance data in DistroSyncDataReq (0x0311) frames. The
`instance_data` field MUST include the metadata block for all instances.


---

## 7. Configuration Management

### 7.1. Chunk Segmentation

Configuration distribution supports data sizes exceeding typical maximum segment
limits. To mitigate Head-of-Line blocking over the multiplexed stream, payloads
exceeding 1,048,576 octets (1MB) MUST be split by the server into independent
sequential chunks via ConfigResponse (OpCode 0x0202).

```rust
ConfigResponse {
    tenant: String,
    group: String,
    data_id: String,
    md5: [u8; 16],       // Raw 128-bit MD5 digest
    total_chunks: u16,   // Total segmented blocks
    chunk_index: u16,    // Relative zero-indexed positioning
    is_deleted: bool,
    raw_bytes: Vec<u8>   // Sliced block bounded to <= 64KB
}
```

While processing multi-chunk frames, the client's packet router SHALL continue
executing interleaving HeartbeatPing frames, ensuring keep-alive health tracking
remains unimpeded during bulk I/O transfers.

### 7.2. Encrypted Config Transport

#### 7.2.1. Design Goals

- Zero-change to non-config OpCodes: only ConfigResponse (0x0202) and
  ConfigChangedNotify (0x0204) bodies are affected
- Backward-compatible: plaintext delivery remains the default
- Per-session key derivation: no shared static encryption keys
- Minimal overhead: AES-256-GCM adds only 33 bytes per encrypted payload
- Replay protection: the IV provides implicit replay detection

#### 7.2.2. FLAG_ENCRYPTED Header Bit

When FLAG_ENCRYPTED (0x10) is set in the header flags byte, the body area is
interpreted using the Encrypted Body Layout instead of the standard layout.

The FLAG_ENCRYPTED bit is valid ONLY for OpCodes 0x0202 and 0x0204. Servers
MUST NOT set FLAG_ENCRYPTED on any other OpCode. Clients receiving
FLAG_ENCRYPTED on an unexpected OpCode MUST close the stream with a protocol
error.

Complete flag allocation:

| Value | Name | Meaning |
|-------|------|---------|
| 0x01 | FLAG_REQUEST | Request/Response indicator |
| 0x02 | FLAG_COMPRESSION | Zstd compressed payload |
| 0x04 | FLAG_BACKPRESSURE | Cluster backpressure |
| 0x08 | FLAG_REDIRECT | Node redirect |
| 0x10 | FLAG_ENCRYPTED | Encrypted body (config only) |
| 0x40 | FLAG_PROBING | Circuit breaker probe |
| 0x80 | FLAG_GOVERNANCE | Governance block present |

#### 7.2.3. Cipher Suite Negotiation

Encryption parameters are negotiated during the handshake via the MessagePack
metadata area.

**Client-Side Metadata (HandshakeRequest)**:

| Key | Type | Example |
|-----|------|---------|
| config_encrypt | bool | true |
| config_cipher_suites | array | ["AES-256-GCM"] |

If `config_encrypt` is absent or false, the server MUST deliver all config
payloads in plaintext.

**Server-Side Metadata (HandshakeResponse)**:

| Key | Type | Example |
|-----|------|---------|
| config_cipher_suite | string | "AES-256-GCM" |
| config_key_id | string | "cek-20260726-a3f1" |
| config_key_rotation_ms | uint64 | 3600000 |

#### 7.2.4. Key Derivation

The Content Encryption Key (CEK) is derived using HKDF-SHA256:

```
session_secret = HMAC-SHA256(client_id + timestamp, shared_key)

CEK = HKDF-SHA256(
    ikm  = session_secret,
    salt = "hmmp-config-encrypt-v1",
    info = config_key_id,
    length = 32 bytes
)
```

Both client and server MUST derive the identical CEK. When
`config_key_rotation_ms` elapses, the server issues a new `config_key_id` and
the client re-derives without tearing down the connection.

#### 7.2.5. Encrypted Body Layout

```
+----------------+----------------+----------------+----------------+
| iv_len (u8)    |      IV (12B)  |  ciphertext_len(u32)           |
+----------------+----------------+----------------+----------------+
|                     ciphertext (variable)                        |
+----------------+----------------+----------------+----------------+
|                  GCM auth tag (16B, within ciphertext)           |
+----------------+----------------+----------------+----------------+
```

| Field | Description |
|-------|-------------|
| iv_len (u8) | Length of IV. MUST be 12 (0x0C) for AES-256-GCM |
| IV | Random 96-bit initialization vector. MUST be unique per encryption operation |
| ciphertext_len (u32) | Length of ciphertext INCLUDING 16-byte GCM auth tag |
| ciphertext | AES-256-GCM encrypted standard body layout |

**Additional Authenticated Data (AAD)**:

    AAD = magic(2B) || version(1B) || stream_id(4B) || body_type(2B)

This binds the ciphertext to the specific frame context, preventing cross-stream
or cross-OpCode ciphertext substitution attacks.

#### 7.2.6. Chunked Transfer and Encryption

When a config payload exceeds 1 MiB, each chunk is encrypted independently with
a unique IV. The chunk header fields are included in the plaintext that gets
encrypted, ensuring chunk integrity and ordering cannot be tampered with.

The client MUST:
1. Decrypt each chunk independently
2. Verify the GCM authentication tag
3. Reassemble the full payload from decrypted chunks
4. Verify the final MD5 over the reassembled content

#### 7.2.7. Error Handling

**Decryption Failure**: If AES-GCM tag verification fails, the client MUST
discard the frame, log a warning, NOT deliver partial content, and request a
fresh GetConfig.

**Key Rotation Failure**: After 3 consecutive decryption failures, client falls
back to plaintext GetConfig and issues a new HandshakeRequest to re-negotiate.

### 7.3. Canary Release (Gray Distribution)

#### 7.3.1. Design Goals

- Server-driven matching: the server decides which config version a client
  receives based on declared labels
- Zero additional OpCodes: reuses existing GetConfig/ListenConfig/
  ConfigChangedNotify with extended fields
- Client transparency: the client does not need to know it is receiving a
  canary version vs. stable version
- Fallback safety: if canary matching fails, clients automatically revert to
  the stable version

#### 7.3.2. Canary Label Model

Labels are key-value string pairs that describe client attributes:

| Key | Example Values | Purpose |
|-----|---------------|---------|
| app_version | "2.3.1", "2.4.0-rc1" | Application version |
| region | "cn-east-1", "us-west" | Deployment region |
| env | "canary", "staging" | Environment tier |
| node_id | "node-42" | Unique instance ID |
| weight | "10" | Traffic weight group |
| zone | "zone-a" | Availability zone |

Constraints: Maximum 16 labels per client; key length 1-64 bytes; value length
0-256 bytes; keys MUST be ASCII lowercase with hyphens `[a-z0-9-]+`; prefix
`hmmp.` is reserved.

#### 7.3.3. Label Declaration via Handshake

The client declares canary labels in HandshakeRequest metadata:

| Key | Type | Example |
|-----|------|---------|
| canary_labels | map | {"app_version": "2.4.0-rc1", "region": "cn-east-1"} |

The server MAY acknowledge in HandshakeResponse:

| Key | Type | Example |
|-----|------|---------|
| canary_enabled | bool | true |
| canary_match_result | map | {"app.yaml": "v2-canary", "db.yaml": "stable"} |

#### 7.3.4. Server-Side Canary Matching

The server maintains a canary rule set per (tenant, group):

```yaml
canary_rule:
  version_id:   "v2-canary"
  content:      "..."
  match_rules:
    - key: "app_version"
      op:  "prefix"        # eq | prefix | regex | in
      value: "2.4.0"
    - key: "env"
      op:  "eq"
      value: "canary"
  percent:      10          # max % of clients
  stable_version_id: "v1-stable"
```

Match evaluation:
1. ALL rules within a canary_rule MUST match (AND logic)
2. Multiple canary_rules evaluated in priority order (first match wins)
3. No rule matches → stable version returned
4. Percent-based sampling uses consistent hashing of (client_id + dataId) for
   sticky canary

#### 7.3.5. Extended GetConfigRequest (0x0201)

Trailing canary context block appended to standard layout:

| Field | Type | Description |
|-------|------|-------------|
| has_canary | u8 | 0x01 = canary context present |
| canary_labels_count | u8 | Number of label entries (0-16) |
| canary_labels_array | Array | key_len(u8)+key + value_len(u8)+value |

#### 7.3.6. Extended ConfigResponse (0x0202)

Trailing canary context:

| Field | Type | Description |
|-------|------|-------------|
| has_canary | u8 | 0x01 = canary context present |
| version_id_len | u16 | + version_id (UTF-8) |
| stable_version_id_len | u16 | + stable_version_id (UTF-8) |
| match_labels_count | u8 | Number of matched labels |
| match_labels_array | Array | Labels that caused the match |

If `version_id != stable_version_id`, the client is receiving a canary version.

#### 7.3.7. Extended ConfigChangedNotify (0x0204)

| Field | Type | Description |
|-------|------|-------------|
| has_canary | u8 | 0x01 = canary context present |
| version_id_len | u16 | + version_id |
| changed_reason | u8 | Reason for the change |

Changed reason values:

| Value | Name | Client Action |
|-------|------|---------------|
| 0x01 | content_updated | Issue GetConfig with labels |
| 0x02 | canary_promoted | Canary → stable; clear canary version_id |
| 0x03 | canary_withdrawn | Immediate GetConfig to revert to stable |
| 0x04 | canary_rule_changed | Issue GetConfig to re-evaluate |

#### 7.3.8. Canary Version Vector

The client maintains a local canary version vector:

```
Map<String, CanaryVersion> canaryVersions;

CanaryVersion:
  versionId:         "v2-canary"
  stableVersionId:   "v1-stable"
  md5:               byte[16]
  receivedAt:        Instant
```

### 7.4. Interaction Between Encryption and Canary

When both extensions are active:
1. Canary matching is performed BEFORE encryption
2. The matched version's content is encrypted using the session CEK
3. Canary extension fields are included in the plaintext that gets encrypted

Frame processing order:

    Sending: canary_match → build plaintext → AES-256-GCM encrypt → set FLAG_ENCRYPTED → write
    Receiving: check FLAG_ENCRYPTED → AES-256-GCM decrypt → parse body → extract canary → deliver

### 7.5. Binary Layout: ListenConfigRequest (0x0203)

| Field | Type | Description |
|-------|------|-------------|
| listen_count | u16 | Number of configs to watch |
| listen_array | Array Block | Subscribed descriptors |

Each entry:

| Field | Type | Description |
|-------|------|-------------|
| tenant_len | u8 | Length of Tenant string |
| tenant | variable | Namespace identifier |
| group_len | u8 | Length of Group string |
| group | variable | Service domain scoping |
| data_id_len | u8 | Length of Configuration ID |
| data_id | variable | Unique file locator token |
| current_md5 | 16 bytes | Raw MD5 digest binary |

### 7.6. Binary Layout: ConfigChangedNotify (0x0204)

| Field | Type | Description |
|-------|------|-------------|
| tenant | u16(len) + UTF-8 | Tenant identifier |
| group | u16(len) + UTF-8 | Configuration group |
| data_id | u16(len) + UTF-8 | Configuration data ID |
| new_md5 | 16 bytes | New MD5 digest (binary) |

### 7.7. Backward Compatibility

- **Old client + New server**: Server sends plaintext. No change.
- **New client + Old server**: Server ignores extension metadata, sends
  plaintext. Client accepts. No change.
- **New client + New server**: Full encrypted + canary transport activated.

---

## 8. Governance Extension

This framework introduces an explicit, backward-compatible "Governance Extension
Block" layout using a type-length-value (TLV) binary taxonomy embedded directly
beneath the multiplex header. It formalizes native wire-level circuit breaking
fast-fail semantics, distributed context tracing, asymmetrical traffic coloring,
decentralized outlier detection voting networks, and two-phase graceful instance
de-registration.

### 8.1. Governance Envelope Mechanics

HMMP version 07 designates Bit 7 (0x80) of the Flags block as the "Governance
Present Indicator".

- **Bit 7 = 0**: Standard data frame. Header is followed immediately by the
  conventional message Body section.
- **Bit 7 = 1**: Governance Active. The 16-byte fixed header MUST be followed
  immediately by a 4-byte unsigned integer specifying the total length of the
  Governance Extension Block, which precedes the normal Body segment.

### 8.2. Governance Extension Block Layout (TLV)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Governance Total Length (32-bit)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Tag Type    |          Tag Length           |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+               +
|                     Tag Value (Variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Registered Tag Types**:

| Tag | Name | Length | Description |
|-----|------|--------|-------------|
| 0x01 | Distributed Trace Context | 24 bytes fixed | Bytes 0-15: TraceID (128-bit, OpenTelemetry); Bytes 16-23: SpanID (64-bit) |
| 0x02 | Traffic Coloring Tag | Variable (max 255) | UTF-8 routing metadata (e.g. "env=gray", "lane=canary-3") |
| 0x03 | Method Metrics Telemetry | 8 bytes fixed | Bytes 0-3: queue duration (u32, μs); Bytes 4-7: execution duration (u32, ms) |
| 0x04 | Tenant Quota Token | 16 bytes fixed | Tenant hashes for wire-level rate limiting |

### 8.3. Native Wire-Level Circuit Breaking

#### 8.3.1. Status Bit Specifications

| Code | Name | Semantics |
|------|------|-----------|
| 0x85 | STATUS_CIRCUIT_BREAKER_OPEN | Target Service Key has breached error limits. Client SDK MUST intercept all subsequent requests locally and return fallback |
| 0x86 | STATUS_INSTANCE_DEGRADED | Instance experiencing critical saturation. Non-essential streams blocked via wire-level rate limiting |

#### 8.3.2. Probing Flag Lifecycle (Half-Open Self-Healing)

Once a client SDK circuit breaker enters its cooling window (Half-Open state),
test streams MUST append Header Flag Bit 6 (0x40) designated as the "Probing
Flow Flag".

Upon parsing Bit 6, the server handles the packet even under load shedding,
ensuring the client can accurately track success rates to determine full
recovery or re-circuit triggers.

### 8.4. Distributed Outlier Voting

Under AP (Gossip) environments, nodes track peer network latencies. If a node
consistently returns malformed checksums or times out, peers utilize OpCode
0x0311 (DistroSyncDataReq) with sync_type = 0x03 (Outlier Vote):

| Field | Type | Description |
|-------|------|-------------|
| source_server_id | u64 | Server ID issuing vote |
| sync_type | u8 | 0x03: Outlier Vote |
| suspect_server_id | u64 | Server ID targeted |
| error_rate_pack | u32 | Quantized error bits |

When any node aggregates votes exceeding floor(N/2)+1 against a suspect, the
target is flagged as "Isolating" across all local routing tables. The client
SDK is notified to steer streams away until probing tests pass.

### 8.5. InstanceShutdownPrepareNotice (0x0006)

A node preparing to shut down MUST broadcast this frame to all connected client
SDK channels. This is a Notify OpCode: stream_id MUST be 0x00000000.

| Field | Type | Description |
|-------|------|-------------|
| shutdown_delay_ms | u32 | Countdown until hard drop (milliseconds) |

Upon receipt, the client SDK:
1. Freezes creation of new Stream IDs on this connection
2. Waits up to `shutdown_delay_ms` for in-flight streams to finalize
3. Initiates reconnection to an alternate node or the cluster FIP


---

## 9. Cluster Specifications

To achieve resilient multi-node convergence without creating additional network
port dependencies, HMMP nodes execute inter-cluster mesh operations over the
standard application port using explicit peer-to-peer signaling.

### 9.1. Peer Identification & Raft Consensus (CP Mode)

#### 9.1.1. Symmetric Single-Port Peer Identification

When an HMMP Server node initiates a link to a configured peer node, it MUST act
as a protocol client on the target's public port but inject the infrastructure
key-value label `"node_type": "cluster_peer"` inside the initial
HandshakeRequest (OpCode 0x0001).

Upon parsing this flag, the receiving server node SHALL bypass default client
tenancy limits, isolate the connection inside a high-priority
`ClusterPeerManager` matrix, and establish a symmetric full-duplex control
channel.

#### 9.1.2. Consistent Persistence Engine (CP Mode)

Persistent entities (such as configuration variables) require strict
linearizable consistency. HMMP enforces this via Raft consensus encapsulated
within OpCodes 0x0301 and 0x0302.

A Follower node receiving a write command from a client MUST intercept the frame
and proxy it to the verified cluster Leader node using the original Stream ID
mapping. The Leader then emits RaftAppendEntriesReq (OpCode 0x0301):

```rust
RaftAppendEntriesReq {
    term: u64,
    leader_id: u64,
    prev_log_index: u64,
    prev_log_term: u64,
    leader_commit: u64,
    entries: Vec<RaftLogEntry>
}
```

#### 9.1.3. OpCode 0x0301: RaftAppendEntriesReq

| Field | Type | Description |
|-------|------|-------------|
| term | u64 | Leader's current term ID |
| leader_id | u64 | Unique ID of active Leader |
| prev_log_index | u64 | Index of preceding log |
| prev_log_term | u64 | Term of prev_log_index |
| leader_commit | u64 | Leader's commitIndex |
| entry_count | u16 | Size of replicated logs |
| entries | Entry Block Array | Sequence of Raft logs |

An `entry_count` of 0x0000 defines an official Consensus Heartbeat packet. Each
entry:

| Field | Type | Description |
|-------|------|-------------|
| entry_index | u64 | Specific log serial number |
| entry_term | u64 | Associated term assignment |
| inner_opcode | u16 | Inner HMMP Command ID |
| payload_len | u32 | Byte length of raw command |
| command_payload | variable | Nested serialization block |

#### 9.1.4. OpCode 0x0302: RaftAppendEntriesRes

| Field | Type | Description |
|-------|------|-------------|
| term | u64 | Follower's term identifier |
| match_log_index | u64 | Highest replicated index |
| success | u8 | 0x01: Appended, 0x00: Fail |
| padding | 3 bytes | Zero alignment |

#### 9.1.5. OpCode 0x0303: RaftRequestVoteReq

Fixed 32 octets:

| Field | Type | Description |
|-------|------|-------------|
| term | u64 | Candidate's current term |
| candidate_id | u64 | Unique identifier of node |
| last_log_index | u64 | Index of candidate's last log entry |
| last_log_term | u64 | Term of candidate's last log entry |

Nodes receiving this frame MUST evaluate `last_log_term` and `last_log_index`
against local storage records before granting a vote.

#### 9.1.6. OpCode 0x0304: RaftRequestVoteRes

Fixed 16 octets:

| Field | Type | Description |
|-------|------|-------------|
| term | u64 | Current term of voter |
| vote_granted | u8 | 0x01: Granted, 0x00: Deny |
| padding | 7 bytes | Alignment boundary zeros |

### 9.2. Distro Replication (AP Mode)

Ephemeral instances utilize a lightweight, high-throughput peer-to-peer gossip
model (Distro replication). When a server node intercepts an instance
registration or a keep-alive HeartbeatPing, it assumes responsibility for that
node's state partition.

The receiving node MUST asynchronously broadcast this event to the remaining
peer connections using DistroSyncDataReq (OpCode 0x0311):

| Field | Type | Description |
|-------|------|-------------|
| source_server_id | u64 | Originating Peer Server ID |
| shard_version | u64 | Monotonically increasing index to drop stale frames |
| sync_type | u8 | 0x00: Register, 0x01: Deregister, 0x02: Renew, 0x03: Outlier Vote |
| service_key | String | Structured lookup format |
| active_connections | u32 | Live concurrent TCP count |
| metrics_pack | u32 | Quantized bits (Section 9.5) |
| real_ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| real_port | u16 | Native physical port |
| instance_data | variable | Direct binary encoding of instance mapping |

Receiving peers update local "shadow registries" without provoking Raft-level
disk serialization, optimizing memory-level horizontal scaling.

### 9.3. Floating IP: CP-Mode Binding

#### 9.3.1. Architecture

A core design goal is "Single-Coordinate Entrance, Distributed Execution". The
infrastructure provisions a single virtual network address designated as the
Floating IP (FIP).

```
             +----------------------------------------------+
             |           Client (SDK Engine)                |
             +----------------------++----------------------+
                                    ||
                                    || (1) Connect via FIP:Port
                                    \/
                     ===============================
                     Floating IP (FIP) - Hosted by Leader
                     ===============================
                                    ||
                                    \/
                       +-------------------------+
                       |   Active Raft Leader    |<----------------+
                       +------------++-----------+                 |
                                    ||                             |
                                    || (2) LeaderRedirectCommand   | (3) NodeLoadReport
                                    ||     (OpCode 0x0313)         |     (OpCode 0x0312)
                                    \/                             |
                       +------------++-----------+                 |
                       |    Follower Node B      |                 |
                       +------------++-----------+                 |
                                    ||                             |
                                    || (4) NodeRedirectNotify      |
                                    ||     (OpCode 0x0005)         |
                                    \/                             |
             +----------------------------------------------+      |
             |         Client Connection Migrates           |------+
             +----------------------------------------------+
```

#### 9.3.2. Consensus-Driven FIP Binding

- **Leader Promotion**: When a node achieves majority quorum via
  RaftRequestVoteRes (0x0304), it MUST broadcast Gratuitous ARP (GARP) or
  perform SDN VPC route overrides to assign the cluster FIP to its physical
  network interface.

- **Demotion & Partition Isolation**: If a node detects a higher Raft Term or
  fails consensus health verification, it MUST immediately yield active FIP
  socket bindings.

#### 9.3.3. OpCode 0x0312: ClusterNodeLoadReport

| Field | Type | Description |
|-------|------|-------------|
| node_id | u64 | Unique Follower Server ID |
| term | u64 | Active validated Raft term |
| active_connections | u32 | Live concurrent TCP count |
| metrics_pack | u32 | Quantized bits (Section 9.5) |
| real_ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| real_port | u16 | Target physical port |
| real_ip_address | 4 or 16 bytes | Raw octets of physical IP |

#### 9.3.4. OpCode 0x0313: ClusterLeaderRedirectCommand

| Field | Type | Description |
|-------|------|-------------|
| leader_term | u64 | Active authorized Raft term |
| target_stream_id | u32 | Target Client Stream ID |
| redirect_reason | u8 | 0x01: Global Overload, 0x03: FIP Resource Shed, 0x04: Local Peer Overload |
| dest_ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| dest_port | u16 | Destination peer port |
| dest_ip_address | 4 or 16 bytes | Destination peer IP |
| graceful_wait_ms | u32 | Milliseconds to clear line |

### 9.4. Floating IP: AP-Mode Preemption

#### 9.4.1. Architecture

In fully symmetrical AP-mode deployments, no centralized authority exists. The
FIP socket binding is acquired and maintained through active competitive leasing.

```
             +----------------------------------------------+
             |           Client (SDK Engine)                |
             +----------------------+-----------------------+
                                    | (1) Initial Connect via FIP
                                    v
                     ===============================
                     Floating IP (FIP) Entrance Map
                     ===============================
                                    |
                                    v
                       +-------------------------+
                       |   AP Peer Node A (FIP)  |<----------------+
                       +------------+------------+                 |
                                    | (2) Overload Local           | (3) Gossip Sync:
                                    |     Redirection Decision     |     DistroSyncDataReq
                                    v                              |     (OpCode 0x0311)
                       +-------------------------+                 |
                       |     AP Peer Node B      |                 |
                       +------------+------------+                 |
                                    |                              |
                                    | (4) ClusterNodeRedirectNotify|
                                    |     (OpCode 0x0005)          |
                                    v                              |
             +----------------------------------------------+      |
             |         Client Connection Migrates           |------+
             +----------------------------------------------+
```

#### 9.4.2. Distributed Lease Preemption

- **Competitive Synchronization**: Every node evaluates the cluster state from
  DistroSyncDataReq broadcasts. The node with the highest quantized compute
  capacity (inverse active connections + low CPU) claims preemption rights.

- **Lease Timeout & Autonomic Preemption**: Each node monitors the FIP holder.
  If heartbeats fail within the timeout window, the next highest-ranking peer
  issues GARP to forcefully bind the FIP.

- **Split-Brain Mitigation**: On partition convergence, the node with higher
  connection count (or smaller Node ID as tiebreaker) prevails; the loser
  immediately unbinds its FIP socket.

#### 9.4.3. OpCode 0x0005: ClusterNodeRedirectNotify

Dispatched by a server node to trigger live connection migration. The server
MUST set Header Flags Bit 3 (R - Node Redirect) to 1.

| Field | Type | Description |
|-------|------|-------------|
| sequence_number | u32 | Migration tracking ID |
| redirect_reason | u8 | 0x01: Global Overload, 0x03: FIP Resource Shed, 0x04: Local Peer Overload |
| graceful_wait_ms | u16 | Milliseconds to clear line |
| target_ip_type | u8 | 0x04: IPv4, 0x06: IPv6 |
| target_port | u16 | Target node port |
| target_ip_address | 4 or 16 bytes | Target node network IP |

#### 9.4.4. Client SDK Connection Migration Algorithm

Upon parsing a redirect frame, the client SDK MUST execute:

1. **Pipeline Gating**: Freeze creation of new Stream IDs on the old socket;
   buffer subsequent transactions.
2. **In-Flight Drainage**: Allow existing streams `graceful_wait_ms` to finalize.
3. **Parallel Link Initialization**: Open secondary TCP channel to target
   address; issue HandshakeRequest (0x0001).
4. **Hot Cutover**: Upon valid HandshakeResponse, switch primary transport to
   new link; dispatch buffered frames; terminate old connection via TCP FIN.

**FIP Home Reversion** (AP mode): If the physical connection to the migration
target fails, the client MUST fall back to the cluster-wide FIP root
configuration using exponential backoff reconnection.

### 9.5. Metrics Pack (32-bit)

To prevent network saturation caused by high-frequency monitoring traffic, HMMP
compresses local node metrics into a 32-bit unsigned bit-map. Microservice
providers SHOULD embed this inside HeartbeatPing (OpCode 0x0003).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   CPU   |  Memory |    Active Conns   |    EWMA Delay   |E|P|R|
+---------+---------+-------------------+-----------------+-----+
  5 bits    5 bits         10 bits             9 bits      3bits
```

| Bits | Field | Range | Description |
|------|-------|-------|-------------|
| 0-4 | CPU | 0-31 | Quantized CPU utilization (×3.22 = percentage) |
| 5-9 | Memory | 0-31 | Quantized RAM allocation (×3.22 = percentage) |
| 10-19 | Active Conns | 0-1023 | Live concurrent connections (clip at 1023) |
| 20-28 | EWMA Delay | 0-511 | Exponentially Weighted Moving Average delay |
| 29 | E - Error | 0/1 | Circuit breakers active or errors > 50% |
| 30 | P - Pre-heating | 0/1 | JIT warmup; load balancer SHOULD throttle |
| 31 | R - Delay Scale | 0/1 | 0 = 1ms resolution; 1 = 10ms resolution (max 5110ms) |


---

## 10. Management Plane: Tenant Lifecycle

The base protocol creates tenants only implicitly — as a side effect of
credential binding, instance registration, or runtime policy override — and
provides no administrative means to create, delete, or inspect a tenant as a
first-class resource. This extension allocates four new request/response OpCode
pairs within the Management Plane range (0x0411-0x0418).

### 10.1. Design Rationale

The implicit-creation model creates three operational problems:

1. **No pre-provisioning**: An operator cannot establish a tenant with a quota
   and policy before handing credentials to a service team.
2. **No decommissioning path**: Once a tenant exists, its resources persist
   indefinitely with no protocol-level removal operation.
3. **No utilisation visibility**: Capacity planning requires runtime counters
   (connections, instances, configurations) not exposed by existing OpCodes.

**Relationship to OpCode 0x0205**: OpCodes 0x0205/0x0206
(TenantAuthorizationOverride) are REMOVED and fully superseded by
AdminUpdateTenantPolicy (0x0413/0x0414). Policy mutation is now exclusively
administrative. The values 0x0205 and 0x0206 are reserved and MUST NOT be
reassigned.

### 10.2. Access Control

All OpCodes in this section are Management Plane operations. A server MUST
reject them with Status Code 1403 unless the originating connection completed a
handshake whose credential record carries `node_type = "admin_console"`. These
OpCodes MUST NOT be accepted on cluster-peer or ordinary business connections.

### 10.3. AdminCreateTenant (0x0411 / 0x0412)

#### Request (0x0411)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        tenant_len (u16)       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                     tenant (UTF-8, variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       policy_flags (u16)      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                   max_connections (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    rate_limit_ops (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  lease_duration_ms (u64)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Type | Description |
|-------|------|-------------|
| tenant_len | u16 | Length of tenant (1-128) |
| tenant | variable | UTF-8 tenant name (Section 10.7 validation) |
| policy_flags | u16 | Bit 0: READ_ONLY; Bit 1: EPHEMERAL_ENFORCE; Bits 2-15: reserved |
| max_connections | u32 | Max concurrent connections (0 = unlimited) |
| rate_limit_ops | u32 | Operations-per-second quota (0 = unlimited) |
| lease_duration_ms | u64 | Lease lifetime in ms (0 = never expires) |

#### Response (0x0412)

Fixed 2 octets: `status_code (u16)`

| Code | Meaning |
|------|---------|
| 0x0000 | Success — tenant created |
| 1404 | Tenant Already Exists |
| 1406 | Invalid Tenant Name |
| 1400 | Bad Request |

### 10.4. AdminUpdateTenantPolicy (0x0413 / 0x0414)

Request body layout is identical to AdminCreateTenantReq. PUT semantics: does
NOT create the tenant if absent; does NOT implicitly renew a lease.

Response status codes: 0x0000 (success), 1407 (Tenant Not Found), 1406
(Invalid Name), 1400 (Bad Request).

### 10.5. AdminDeleteTenant (0x0415 / 0x0416)

#### Request (0x0415)

| Field | Type | Description |
|-------|------|-------------|
| tenant_len | u16 | Length of tenant |
| tenant | variable | UTF-8 tenant name |
| force | u8 | 0 = safe deletion; 1 = force cascade deletion |

#### Response (0x0416)

Status codes: 0x0000 (success), 1407 (Not Found), 1405 (Not Empty, safe mode
only), 1400 (Bad Request).

### 10.6. AdminGetTenantStats (0x0417 / 0x0418)

#### Request (0x0417)

Carries only the tenant string (tenant_len + tenant).

#### Response (0x0418)

Fixed 17 octets:

| Field | Type | Description |
|-------|------|-------------|
| found | u8 | 0 = not found (counters zero); 1 = found |
| active_connections | u32 | AUTHENTICATED connections for this tenant |
| registered_services | u16 | Distinct service names with live instances |
| registered_instances | u32 | Total live instance count |
| credential_count | u16 | Credential records referencing tenant |
| config_count | u32 | Non-deleted configuration items |

### 10.7. Tenant Name Validation

A tenant name MUST satisfy all constraints:

1. **Length**: 1-128 octets of UTF-8
2. **Character set**: ASCII letters (a-z, A-Z), digits (0-9), hyphen (-),
   underscore (_), full stop (.) only
3. **Boundary**: MUST NOT begin or end with hyphen or full stop
4. **Reserved**: "*" (wildcard) MUST NOT be accepted by AdminCreateTenantReq
5. **Case sensitivity**: Names are case-sensitive

ABNF grammar:

    tenant-name = 1*128 tenant-char
    tenant-char = ALPHA / DIGIT / "-" / "_" / "."
    ; first and last char in (ALPHA / DIGIT); literal "*" rejected

### 10.8. Safe Deletion Semantics

When `force = 0`, the server MUST verify the tenant holds no live resources:
- active_connections > 0
- registered_instances > 0
- config_count > 0
- credential_count > 0

If any predicate is true, respond 1405 (no-op).

When `force = 1`, cascade in order:
1. Terminate all connections (InstanceShutdownPrepareNotice with delay=0)
2. Deregister all instances; broadcast ServiceChangedNotify
3. Mark all configs deleted; broadcast ConfigChangedNotify
4. Delete all credential records
5. Delete tenant policy record; release partition

Each step MUST be audit-logged. Force deletion is irreversible.

### 10.9. Status Codes

| Value | Name | Semantics |
|-------|------|-----------|
| 1404 | Tenant Already Exists | Create targeted existing tenant |
| 1405 | Tenant Not Empty | Safe deletion blocked by live resources |
| 1406 | Invalid Tenant Name | Validation failure |
| 1407 | Tenant Not Found | Update/Delete/Stats targeted absent tenant |

---

## 11. Management Plane: Credential Lifecycle

The base protocol stores client credentials (client_id → secret) in the
server's embedded database for HMAC-SHA256 handshake verification, but provides
no administrative means to manage them over the wire. This extension allocates
four OpCode pairs (0x0419-0x0420) enabling full CRUD operations on the server's
credential store.

### 11.1. Motivation

The split-brain credential storage failure mode:
1. Operator creates credential "app-01" via console UI
2. Console stores it in console.db (SQLite)
3. Client "app-01" attempts handshake with server
4. Server looks up "app-01" in hmmp.redb → NOT FOUND
5. Handshake fails

By routing credential mutations through the HMMP management plane, the server's
local store becomes the single source of truth.

### 11.2. AdminCreateCredential (0x0419 / 0x041A)

#### Request (0x0419)

| Field | Type | Description |
|-------|------|-------------|
| client_id | var | String (u16 len + UTF-8) |
| secret | var | String (u16 len + UTF-8) |
| tenant | var | String (u16 len + UTF-8) |
| node_type | var | String (u16 len + UTF-8) |

All four fields are REQUIRED and MUST be non-empty.

#### Response (0x041A)

Fixed 2 octets: status_code (0x0000 = success, 1408 = already exists,
1406 = invalid name, 1400 = decode failure).

### 11.3. AdminUpdateCredential (0x041B / 0x041C)

#### Request (0x041B)

| Field | Type | Description |
|-------|------|-------------|
| client_id | var | String (target credential) |
| has_secret | u8 | 1 = secret field present |
| secret | var | String (if has_secret=1) |
| has_tenant | u8 | 1 = tenant field present |
| tenant | var | String (if has_tenant=1) |
| has_node_type | u8 | 1 = node_type present |
| node_type | var | String (if has_node_type=1) |
| has_enabled | u8 | 1 = enabled field present |
| enabled | u8 | 0/1 (if has_enabled=1) |

Only fields with `has_*=1` are applied; others remain unchanged.

#### Response (0x041C)

Fixed 2 octets: status_code (0x0000 = success, 1409 = not found).

### 11.4. AdminDeleteCredential (0x041D / 0x041E)

Request carries only `client_id` (String). Response: status_code (0x0000 =
success, 1409 = not found).

### 11.5. AdminListCredentials (0x041F / 0x0420)

#### Request (0x041F)

| Field | Type | Description |
|-------|------|-------------|
| tenant_filter | var | String (empty = all tenants) |

#### Response (0x0420)

| Field | Type | Description |
|-------|------|-------------|
| count | u16 | Number of credentials |
| items[] | var | Repeated credential items |

Each item:

| Field | Type | Description |
|-------|------|-------------|
| client_id | var | String |
| tenant | var | String |
| node_type | var | String |
| enabled | u8 | 0 or 1 |
| created_at | u64 | Unix timestamp (ms) |

**Note**: secret is NEVER included in list responses.

### 11.6. Validation Rules

| Field | Rules |
|-------|-------|
| client_id | 1-128 bytes, ASCII alphanumeric + `-`/`_`/`.`; MUST NOT start/end with `-` or `.` |
| secret | 1-256 bytes, arbitrary UTF-8; MUST NOT be empty on create |
| node_type | MUST be one of: "client", "admin_console", "cluster_peer" |
| tenant | Follows tenant name validation (Section 10.7), OR "*" (wildcard) |

### 11.7. Cluster Replication

Credential data is classified as CP (Consistency-Priority) data. In cluster
mode:
1. Leader receives AdminCreateCredentialReq (0x0419)
2. Leader wraps the mutation as a Raft log entry with inner_opcode = 0x0419
3. AppendEntries replicates to followers
4. Each node applies the entry to its local redb credential table
5. Leader responds to client after majority commit

### 11.8. Status Codes

| Code | Name | Semantics |
|------|------|-----------|
| 1408 | CREDENTIAL_ALREADY_EXISTS | Create target already exists |
| 1409 | CREDENTIAL_NOT_FOUND | Update/Delete target not found |

---

## 12. Multi-Tenant Isolation Matrix

To prevent cross-tenant data leakage and ensure strict resource isolation, HMMP
implements a multi-tier tenant scoping matrix based on the `tenant` identifier
(Namespace ID) passed inside metadata blocks or parameters.

```
+-----------------------------------------------------------------+
|                      TCP Connection Layer                       |
|              (Authenticated via Handshake AccessKey)            |
+-----------------------------------------------------------------+
                                 |
              +------------------+------------------+
              |                                     |
+---------------------------+         +---------------------------+
|    Tenant Namespace A     |         |    Tenant Namespace B     |
|    (Logical Isolation)    |         |    (Logical Isolation)    |
+---------------------------+         +---------------------------+
      |               |                     |               |
+-----------+   +-----------+         +-----------+   +-----------+
| Group A1  |   | Group A2  |         | Group B1  |   | Group B2  |
+-----------+   +-----------+         +-----------+   +-----------+
```

### 12.1. Logical Boundary Enforcement

All Naming and Configuration operations MUST carry a validated `tenant`
identifier. The server's registry engine MUST shard service instances and
dynamic configuration data frames using the calculated SHA-256 hash of the
`tenant` name as the primary partition key.

### 12.2. Cross-Tenant Cross-Talk Prevention

A client authenticated under `access_key` "X" MUST NOT query, listen to, or
mutate resources residing within a tenant space that has not been explicitly
granted to "X" in the server's Access Control List (ACL) matrix. Any attempt to
cross this boundary SHALL prompt an immediate response with Status Code 1403
(Tenant Access Denied) and terminate illegal packet execution loops.

### 12.3. Dynamic Quota Control

Multi-tenant controls support dynamic rate limiting per tenant channel. Servers
monitor the concurrent Stream ID consumption rate per tenant namespace. If a
single tenant exceeds its pre-allocated bandwidth or operations-per-second (OPS)
quota, the server SHALL inject an upstream backpressure flag into the Flags
field of subsequent response frames.


---

## 13. Security Considerations

### 13.1. Transport Security

HMMP enforces transport-level security constraints via mandatory HMAC-SHA256
signature verification during handshakes. This mitigates impersonation and
replay vectors. Multi-tenant boundary checks are strictly performed by the
isolation engine for every logical stream to prevent cross-tenant leaking
anomalies.

Cluster-internal synchronization, control plane balancing, and load reports
(OpCodes 0x0300-0x03FF) SHOULD be bound to a separate, cryptographically secure
internal pre-shared key (PSK). Because HMMP payload fields are unencrypted by
default to achieve hardware-level throughput, production deployments MUST
execute HMMP directly within an isolated mTLS wrapper or a protected Virtual
Private Cloud (VPC) network boundary.

### 13.2. Handshake Anti-Replay

- **Nonce Entropy**: Servers MUST use CSPRNG for nonce generation. Predictable
  nonces defeat the replay protection entirely.
- **Nonce Exhaustion DoS**: Rate limit NonceChallengeRequest per source IP
  (recommended: 10 req/s per IP). Use stateless nonce verification to avoid
  storage altogether.
- **Downgrade Attack**: If `allow_legacy_handshake=true`, an active MitM can
  strip the nonce exchange. Set to `false` in production; monitor
  `hmmp.handshake.legacy_count` metric.
- **Timing**: The nonce_ttl_ms window (default 5s) reduces the replay window
  from 300s to 5s — a 60x improvement.

### 13.3. Encrypted Config Transport

- **IV Reuse**: AES-256-GCM is catastrophically vulnerable to IV reuse.
  Implementations MUST use CSPRNG for IV generation. If reuse is detected, the
  session MUST be torn down immediately.
- **Key Compromise**: Key rotation via `config_key_rotation_ms` limits the
  exposure window.
- **Side-Channel Attacks**: AES-GCM implementations MUST use constant-time
  operations.
- **Metadata Leakage**: Frame metadata (body_type, stream_id) and frame size
  remain visible even with encryption enabled.

### 13.4. Canary Release

- **Label Spoofing**: Mitigated by server-side label validation against the
  authenticated client identity (client_id + token).
- **Canary Content Leakage**: Operators SHOULD enable encryption for canary
  distributions.
- **Information Disclosure**: match_labels in ConfigResponse reveals client
  attributes; SHOULD be encrypted.

### 13.5. Governance Extension

Embedding traffic coloring tags and distributed trace IDs inside raw network
envelopes increases exposure to injection attacks. A malicious client could
forge Tenant Quota Tokens (Tag 0x04) or inject synthetic Trace Contexts (Tag
0x01). All governance blocks crossing untrusted perimeters MUST undergo
cryptographic verification inside an mTLS gateway layer.

### 13.6. Cluster Floating IP

- **CP Mode**: Moving the cluster entrance to a Floating IP consolidates the
  perimeter but amplifies DDoS exposure. Internal control loops (0x0312/0x0313)
  MUST be isolated inside a VPC subnet or forced via mTLS.
- **AP Mode**: Open dynamic preemption introduces risk of MAC spoofing, ARP
  poisoning, and malicious peer lease hijacking. All peer-to-peer gossip
  interfaces (0x0311) MUST be validated via pre-shared cryptographic signatures
  or isolated inside a physically segregated VLAN/VPC.

### 13.7. Metadata Extension

- **Metadata Injection**: Servers MUST validate that keys and values do not
  contain control characters (0x00-0x1F except tab/newline).
- **Filter Complexity (ReDoS)**: Servers MUST use RE2 or equivalent linear-time
  regex engine with 100ms compilation timeout.
- **Tenant Isolation**: Filter expressions MUST be evaluated only within the
  requesting tenant's shard.

### 13.8. Management Plane

- **Authorisation**: All Management Plane OpCodes require `node_type =
  "admin_console"`. Accepting them on business connections is a critical
  implementation defect.
- **Credential Secrets**: Transmitted in plaintext within management frames;
  TLS 1.3/mTLS MUST be enabled in production.
- **Force Deletion DoS**: Rate-limit AdminDeleteTenantReq; alert on force=1;
  retain point-in-time snapshots.
- **Audit Trail**: Every mutation MUST be logged with administrator client_id,
  target resource, and timestamp.

---

## 14. Implementation Errata (v07)

This section clarifies ambiguities identified during implementation.

### 14.1. ConfigResponse.md5 Type

Section 7.1 defines ConfigResponse.md5 as a struct field, while Section 7.5
defines current_md5 as "16 bytes raw binary".

**CLARIFICATION**: Both fields MUST use 16-byte raw binary MD5 digest. The
"String" type in early documentation is a documentation error.

### 14.2. HeartbeatPing Empty Body Response

**CLARIFICATION**: Server MUST respond with HeartbeatPong (0x0004) for ALL
HeartbeatPing (0x0003) frames, regardless of body content. Empty body Ping is
valid for keep-alive without load reporting.

### 14.3. Signature Verification Failure Status Code

**CLARIFICATION**: Signature verification failure MUST return 1001 (Timestamp
Expired) to avoid leaking information about whether the timestamp or signature
was the failing factor. This prevents enumeration attacks.

### 14.4. ConfigChangedNotify Body Format

**CLARIFICATION**: ConfigChangedNotify (0x0204) body format is defined in
Section 7.6. The `new_md5` field allows clients to verify cache validity without
issuing a separate GetConfig request.

---

## 15. References

| Ref | Description |
|-----|-------------|
| [RFC2119] | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997 |
| [RFC4086] | Eastlake 3rd, D., et al., "Randomness Requirements for Security", BCP 106, RFC 4086, June 2005 |
| [RFC5116] | McGrew, D., "An Interface and Algorithms for Authenticated Encryption", RFC 5116, January 2008 |
| [RFC5234] | Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008 |
| [RFC5869] | Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010 |
| [RFC8174] | Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017 |
| [NIST-GCM] | Dworkin, M., "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)", NIST SP 800-38D, November 2007 |

---

*End of Specification*
