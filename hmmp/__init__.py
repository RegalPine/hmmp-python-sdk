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

"""HMMP Python Client SDK.

High-Performance Microservice Multiplex Protocol (HMMP) v07 client implementation.

Example usage:

    import asyncio
    from hmmp import HMMPClient, ClientConfig, ServiceInstance

    async def main():
        config = ClientConfig(
            host="127.0.0.1",
            port=8848,
            access_key="my-app",
            secret_key="my-secret",
        )

        async with HMMPClient(config) as client:
            # Register a service instance
            instance = ServiceInstance(
                service_name="user-service",
                ip="192.168.1.100",
                port=8080,
                weight=1.0,
            )
            await client.register_instance(instance)

            # Discover services
            snapshot = await client.discover_service("user-service")
            for inst in snapshot.instances:
                print(f"Found: {inst.ip}:{inst.port}")

            # Get configuration
            config_entry = await client.get_config("app.yaml", group="DEFAULT_GROUP")
            print(config_entry.content_str)

    asyncio.run(main())
"""

from __future__ import annotations

__version__ = "0.7.0"

# Client
from .client import ClientConfig, HMMPClient

# Models
from .models import (
    ConfigChangedNotification,
    ConfigEntry,
    CredentialInfo,
    FilterExpression,
    FilteredServiceSnapshot,
    HandshakeResult,
    ListenConfigEntry,
    NonceChallengeResult,
    RedirectInfo,
    ServiceInstance,
    ServiceSnapshot,
    ShutdownNotice,
    TenantStats,
)

# Constants
from .constants import (
    AddressFamily,
    CircuitBreakerStatus,
    ConfigChangedReason,
    FilterNodeType,
    FilterOperator,
    Flag,
    GovernanceTag,
    IpType,
    OpCode,
    RedirectReason,
    StatusCode,
    SyncType,
)

# Exceptions
from .exceptions import (
    AuthenticationError,
    BackpressureError,
    CircuitBreakerOpenError,
    ConfigError,
    ConnectionClosedError,
    ConnectionError,
    DecryptionError,
    FilterExpressionError,
    HandshakeError,
    HandshakeTimeoutError,
    HMMPError,
    MetadataLimitError,
    NonceError,
    ProtocolError,
    RedirectError,
    ServiceError,
    ShutdownNoticeError,
    StreamError,
    TenantAccessDeniedError,
    TimeoutError,
)

# Codec utilities
from .codec import (
    BinaryReader,
    BinaryWriter,
    bytes_to_ip,
    compute_metadata_hash,
    fnv1a_64,
    ip_to_bytes,
    pack_metrics_pack,
    unpack_metrics_pack,
)

# Crypto utilities
from .crypto import (
    compute_md5,
    compute_signature,
    compute_signature_v2,
    decrypt_config_body,
    derive_cek,
    derive_session_secret,
    encrypt_config_body,
    verify_md5,
    verify_signature,
    verify_signature_v2,
)

# Frame
from .frame import Frame, FrameDecoder, FrameEncoder, FrameHeader

# Governance
from .governance import (
    GovernanceBlock,
    MethodMetrics,
    TenantQuotaToken,
    TraceContext,
    TrafficColoring,
    build_governance_block,
    parse_governance_block,
)

# Circuit Breaker
from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitState,
)

# Backpressure
from .backpressure import BackpressureController

# Metrics
from .metrics import MetricsCollector

# Cache
from .cache import (
    CanaryVersion,
    CanaryVersionVector,
    ConfigCache,
    ServiceSnapshotCache,
)

# Admin Service
from .admin import (
    AdminConfigItem,
    AdminService,
    AdminTenantItem,
    GovernanceState,
    TenantPolicy,
)

# Frame Interceptor
from .interceptor import (
    CompositeFrameInterceptor,
    FrameInterceptor,
    GovernanceFrameInterceptor,
)

# Load Balancer
from .load_balancer import (
    AdaptiveLoadBalancer,
    TrafficColorRouter,
    WeightedInstance,
)

__all__ = [
    # Version
    "__version__",
    # Client
    "HMMPClient",
    "ClientConfig",
    # Models
    "ServiceInstance",
    "ServiceSnapshot",
    "FilteredServiceSnapshot",
    "ConfigEntry",
    "ConfigChangedNotification",
    "ListenConfigEntry",
    "FilterExpression",
    "HandshakeResult",
    "NonceChallengeResult",
    "RedirectInfo",
    "ShutdownNotice",
    "TenantStats",
    "CredentialInfo",
    # Constants
    "OpCode",
    "Flag",
    "StatusCode",
    "IpType",
    "AddressFamily",
    "SyncType",
    "RedirectReason",
    "ConfigChangedReason",
    "FilterNodeType",
    "FilterOperator",
    "GovernanceTag",
    "CircuitBreakerStatus",
    # Exceptions
    "HMMPError",
    "ProtocolError",
    "ConnectionError",
    "ConnectionClosedError",
    "HandshakeError",
    "HandshakeTimeoutError",
    "NonceError",
    "AuthenticationError",
    "TenantAccessDeniedError",
    "TimeoutError",
    "StreamError",
    "DecryptionError",
    "ConfigError",
    "ServiceError",
    "RedirectError",
    "ShutdownNoticeError",
    "BackpressureError",
    "CircuitBreakerOpenError",
    "MetadataLimitError",
    "FilterExpressionError",
    # Codec
    "BinaryReader",
    "BinaryWriter",
    "ip_to_bytes",
    "bytes_to_ip",
    "fnv1a_64",
    "compute_metadata_hash",
    "pack_metrics_pack",
    "unpack_metrics_pack",
    # Crypto
    "compute_signature",
    "compute_signature_v2",
    "verify_signature",
    "verify_signature_v2",
    "derive_session_secret",
    "derive_cek",
    "encrypt_config_body",
    "decrypt_config_body",
    "compute_md5",
    "verify_md5",
    # Frame
    "Frame",
    "FrameHeader",
    "FrameEncoder",
    "FrameDecoder",
    # Governance
    "GovernanceBlock",
    "TraceContext",
    "TrafficColoring",
    "MethodMetrics",
    "TenantQuotaToken",
    "parse_governance_block",
    "build_governance_block",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerRegistry",
    "CircuitState",
    # Backpressure
    "BackpressureController",
    # Metrics
    "MetricsCollector",
    # Cache
    "CanaryVersion",
    "CanaryVersionVector",
    "ConfigCache",
    "ServiceSnapshotCache",
    # Admin
    "AdminService",
    "AdminConfigItem",
    "AdminTenantItem",
    "TenantPolicy",
    "GovernanceState",
    # Interceptor
    "FrameInterceptor",
    "GovernanceFrameInterceptor",
    "CompositeFrameInterceptor",
    # Load Balancer
    "AdaptiveLoadBalancer",
    "TrafficColorRouter",
    "WeightedInstance",
]
