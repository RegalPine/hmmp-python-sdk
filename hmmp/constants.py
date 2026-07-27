# Copyright 2026 The HMMP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HMMP protocol constants: OpCodes, Flags, Status Codes."""

from enum import IntEnum, IntFlag

# Protocol constants
MAGIC_NUMBER = 0x5153
PROTOCOL_VERSION = 0x07
HEADER_SIZE = 16
MAX_PAYLOAD_SIZE = 4_294_967_295
MAX_TIMESTAMP_DRIFT_MS = 300_000  # 300 seconds
HANDSHAKE_TIMEOUT_MS = 3000
DEFAULT_NONCE_TTL_MS = 5000
MAX_NONCE_TTL_MS = 30000
CONFIG_CHUNK_SIZE = 1_048_576  # 1MB
CONFIG_MAX_CHUNK_BYTES = 65_536  # 64KB


class Flag(IntFlag):
    """Frame header flags (8-bit bitmask)."""
    REQUEST = 0x01
    COMPRESSION = 0x02
    BACKPRESSURE = 0x04
    REDIRECT = 0x08
    ENCRYPTED = 0x10
    PROBING = 0x40
    GOVERNANCE = 0x80


class OpCode(IntEnum):
    """HMMP operation codes."""
    # Connection Lifecycle (0x0001-0x00FF)
    HANDSHAKE_REQUEST = 0x0001
    HANDSHAKE_RESPONSE = 0x0002
    HEARTBEAT_PING = 0x0003
    HEARTBEAT_PONG = 0x0004
    CLUSTER_NODE_REDIRECT_NOTIFY = 0x0005
    INSTANCE_SHUTDOWN_PREPARE_NOTICE = 0x0006
    NONCE_CHALLENGE_REQUEST = 0x0007
    NONCE_CHALLENGE_RESPONSE = 0x0008

    # Naming & Discovery (0x0100-0x01FF)
    REGISTER_INSTANCE_REQUEST = 0x0101
    DEREGISTER_INSTANCE_REQUEST = 0x0103
    DISCOVER_SERVICE_REQUEST = 0x0105
    DISCOVER_SERVICE_RESPONSE = 0x0106
    SERVICE_CHANGED_NOTIFY = 0x0108
    REGISTER_INSTANCE_WITH_META_REQUEST = 0x0109
    REGISTER_INSTANCE_WITH_META_RESPONSE = 0x010A
    DISCOVER_SERVICE_BY_FILTER_REQUEST = 0x010B
    DISCOVER_SERVICE_BY_FILTER_RESPONSE = 0x010C

    # Configuration Management (0x0200-0x02FF)
    GET_CONFIG_REQUEST = 0x0201
    CONFIG_RESPONSE = 0x0202
    LISTEN_CONFIG_REQUEST = 0x0203
    CONFIG_CHANGED_NOTIFY = 0x0204

    # Cluster Control (0x0300-0x03FF) - Server-to-Server
    RAFT_APPEND_ENTRIES_REQ = 0x0301
    RAFT_APPEND_ENTRIES_RES = 0x0302
    RAFT_REQUEST_VOTE_REQ = 0x0303
    RAFT_REQUEST_VOTE_RES = 0x0304
    DISTRO_SYNC_DATA_REQ = 0x0311
    CLUSTER_NODE_LOAD_REPORT = 0x0312
    CLUSTER_LEADER_REDIRECT_COMMAND = 0x0313

    # Management Plane (0x0400-0x04FF)
    ADMIN_CREATE_TENANT_REQ = 0x0411
    ADMIN_CREATE_TENANT_RES = 0x0412
    ADMIN_UPDATE_TENANT_POLICY_REQ = 0x0413
    ADMIN_UPDATE_TENANT_POLICY_RES = 0x0414
    ADMIN_DELETE_TENANT_REQ = 0x0415
    ADMIN_DELETE_TENANT_RES = 0x0416
    ADMIN_GET_TENANT_STATS_REQ = 0x0417
    ADMIN_GET_TENANT_STATS_RES = 0x0418
    ADMIN_CREATE_CREDENTIAL_REQ = 0x0419
    ADMIN_CREATE_CREDENTIAL_RES = 0x041A
    ADMIN_UPDATE_CREDENTIAL_REQ = 0x041B
    ADMIN_UPDATE_CREDENTIAL_RES = 0x041C
    ADMIN_DELETE_CREDENTIAL_REQ = 0x041D
    ADMIN_DELETE_CREDENTIAL_RES = 0x041E
    ADMIN_LIST_CREDENTIALS_REQ = 0x041F
    ADMIN_LIST_CREDENTIALS_RES = 0x0420


class StatusCode(IntEnum):
    """HMMP status codes."""
    OK = 0x0000
    TIMESTAMP_EXPIRED = 1001
    NONCE_ALREADY_CONSUMED = 0x0003
    NONCE_REQUIRED = 0x0004
    BAD_REQUEST = 1400
    TENANT_ACCESS_DENIED = 1403
    TENANT_ALREADY_EXISTS = 1404
    TENANT_NOT_EMPTY = 1405
    INVALID_TENANT_NAME = 1406
    TENANT_NOT_FOUND = 1407
    CREDENTIAL_ALREADY_EXISTS = 1408
    CREDENTIAL_NOT_FOUND = 1409
    METADATA_LIMIT_EXCEEDED = 1400


class NonceStatus(IntEnum):
    """Nonce challenge response status codes."""
    OK = 0x0000
    TIMESTAMP_DRIFT = 0x0001
    RATE_LIMITED = 0x0002


class IpType(IntEnum):
    """IP address type identifiers."""
    IPV4 = 0x04
    IPV6 = 0x06


class AddressFamily(IntEnum):
    """Address family for deregistration."""
    IPV4 = 0x0001
    IPV6 = 0x0002


class SyncType(IntEnum):
    """Distro sync types."""
    REGISTER = 0x00
    DEREGISTER = 0x01
    RENEW = 0x02
    OUTLIER_VOTE = 0x03


class RedirectReason(IntEnum):
    """Redirect reason codes."""
    GLOBAL_OVERLOAD = 0x01
    FIP_RESOURCE_SHED = 0x03
    LOCAL_PEER_OVERLOAD = 0x04


class ConfigChangedReason(IntEnum):
    """Config changed notification reasons."""
    CONTENT_UPDATED = 0x01
    CANARY_PROMOTED = 0x02
    CANARY_WITHDRAWN = 0x03
    CANARY_RULE_CHANGED = 0x04


class FilterNodeType(IntEnum):
    """Filter expression node types."""
    LEAF = 0x01
    AND = 0x02
    OR = 0x03
    NOT = 0x04


class FilterOperator(IntEnum):
    """Filter comparison operators."""
    EQ = 0x01
    NE = 0x02
    PREFIX = 0x03
    CONTAINS = 0x04
    IN = 0x05
    EXISTS = 0x06
    NOT_EXISTS = 0x07
    REGEX = 0x08


class GovernanceTag(IntEnum):
    """Governance TLV tag types."""
    TRACE_CONTEXT = 0x01
    TRAFFIC_COLORING = 0x02
    METHOD_METRICS = 0x03
    TENANT_QUOTA_TOKEN = 0x04


class CircuitBreakerStatus(IntEnum):
    """Circuit breaker status codes."""
    OPEN = 0x85
    INSTANCE_DEGRADED = 0x86


# Metadata keys
META_TRACE_ID = "trace_id"
META_TOKEN = "token"
META_CLIENT_VERSION = "client_version"
META_BODY_TYPE = "body_type"

# Handshake metadata keys
META_CONFIG_ENCRYPT = "config_encrypt"
META_CONFIG_CIPHER_SUITES = "config_cipher_suites"
META_CONFIG_CIPHER_SUITE = "config_cipher_suite"
META_CONFIG_KEY_ID = "config_key_id"
META_CONFIG_KEY_ROTATION_MS = "config_key_rotation_ms"
META_CANARY_LABELS = "canary_labels"
META_CANARY_ENABLED = "canary_enabled"
META_CANARY_MATCH_RESULT = "canary_match_result"

# Node type labels
NODE_TYPE_CLIENT = "client"
NODE_TYPE_ADMIN_CONSOLE = "admin_console"
NODE_TYPE_CLUSTER_PEER = "cluster_peer"

# FNV-1a hash constants
FNV_OFFSET_BASIS = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
