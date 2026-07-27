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

"""HMMP protocol exceptions."""

from __future__ import annotations


class HMMPError(Exception):
    """Base exception for all HMMP errors."""


class ProtocolError(HMMPError):
    """Protocol-level error (malformed frame, invalid magic, etc.)."""


class ConnectionError(HMMPError):
    """Connection-level error."""


class ConnectionClosedError(ConnectionError):
    """Connection was closed unexpectedly."""


class HandshakeError(HMMPError):
    """Handshake failed."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class HandshakeTimeoutError(HandshakeError):
    """Handshake timed out."""


class NonceError(HandshakeError):
    """Nonce challenge failed."""


class AuthenticationError(HMMPError):
    """Authentication/authorization failed."""


class TenantAccessDeniedError(AuthenticationError):
    """Cross-tenant access denied (status 1403)."""


class TimeoutError(HMMPError):
    """Operation timed out."""


class StreamError(HMMPError):
    """Stream-level error."""

    def __init__(self, message: str, stream_id: int | None = None):
        super().__init__(message)
        self.stream_id = stream_id


class DecryptionError(HMMPError):
    """AES-GCM decryption or tag verification failed."""


class ConfigError(HMMPError):
    """Configuration operation error."""


class ServiceError(HMMPError):
    """Service discovery/registration error."""


class RedirectError(HMMPError):
    """Server requested connection redirect."""

    def __init__(
        self,
        message: str,
        target_ip: str,
        target_port: int,
        graceful_wait_ms: int,
        reason: int,
    ):
        super().__init__(message)
        self.target_ip = target_ip
        self.target_port = target_port
        self.graceful_wait_ms = graceful_wait_ms
        self.reason = reason


class ShutdownNoticeError(HMMPError):
    """Server is preparing to shut down."""

    def __init__(self, message: str, shutdown_delay_ms: int):
        super().__init__(message)
        self.shutdown_delay_ms = shutdown_delay_ms


class BackpressureError(HMMPError):
    """Server signaled backpressure."""


class CircuitBreakerOpenError(HMMPError):
    """Circuit breaker is open for target service."""


class MetadataLimitError(HMMPError):
    """Metadata constraints exceeded."""


class FilterExpressionError(HMMPError):
    """Invalid filter expression."""
