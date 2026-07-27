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

"""Frame interceptor for HMMP protocol.

Provides hooks for governance layer to inject TLV tags and process
response governance signals.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .constants import CircuitBreakerStatus, Flag
from .governance import GovernanceBlock, parse_governance_block

if TYPE_CHECKING:
    from .frame import Frame

logger = logging.getLogger(__name__)


class FrameInterceptor(ABC):
    """Abstract interceptor for outgoing/incoming frames.

    Used by governance layer to inject TLV tags and process response signals.
    """

    @abstractmethod
    def on_before_send(self, frame_data: bytes, opcode: int) -> bytes:
        """Called before a request frame is sent.

        Allows enrichment (e.g., governance TLV injection).

        Args:
            frame_data: Encoded frame bytes
            opcode: OpCode of the frame

        Returns:
            Possibly modified frame bytes
        """
        return frame_data

    @abstractmethod
    def on_after_receive(self, frame: Frame) -> bool:
        """Called after a response frame is received.

        Allows processing governance signals.

        Args:
            frame: Received frame

        Returns:
            True if the response indicates a governance error
            (e.g., 0x85 circuit breaker open)
        """
        return False


class GovernanceFrameInterceptor(FrameInterceptor):
    """Governance-aware frame interceptor.

    Injects trace context and traffic coloring into outgoing frames,
    and processes circuit breaker signals from incoming frames.
    """

    def __init__(
        self,
        trace_id: bytes | None = None,
        span_id: bytes | None = None,
        traffic_tag: str | None = None,
    ):
        self._trace_id = trace_id
        self._span_id = span_id
        self._traffic_tag = traffic_tag
        self._circuit_breaker_open_services: set[str] = set()

    def set_trace_context(self, trace_id: bytes, span_id: bytes) -> None:
        """Set distributed trace context for outgoing frames."""
        self._trace_id = trace_id
        self._span_id = span_id

    def set_traffic_tag(self, tag: str) -> None:
        """Set traffic coloring tag for outgoing frames."""
        self._traffic_tag = tag

    def on_before_send(self, frame_data: bytes, opcode: int) -> bytes:
        """Inject governance TLV into outgoing frame if configured.

        Note: This is a simplified implementation. Full implementation would
        need to rebuild the frame with governance block inserted.
        """
        # For now, we don't modify the frame data directly
        # The governance block should be set during frame encoding
        return frame_data

    def on_after_receive(self, frame: Frame) -> bool:
        """Process governance signals from incoming frame.

        Checks for:
        - Circuit breaker open status (0x85)
        - Instance degraded status (0x86)
        - Governance TLV block
        """
        is_governance_error = False

        # Check for circuit breaker status in body (if applicable)
        # Status codes 0x85/0x86 may appear in response bodies
        if frame.body and len(frame.body) >= 1:
            status = frame.body[0]
            if status == CircuitBreakerStatus.OPEN:
                logger.warning(
                    f"Circuit breaker OPEN signaled for stream {frame.stream_id}"
                )
                is_governance_error = True
            elif status == CircuitBreakerStatus.INSTANCE_DEGRADED:
                logger.warning(
                    f"Instance DEGRADED signaled for stream {frame.stream_id}"
                )

        # Parse governance block if present
        if frame.governance_block:
            try:
                gov = parse_governance_block(frame.governance_block)
                self._process_governance_block(gov, frame)
            except Exception as e:
                logger.debug(f"Failed to parse governance block: {e}")

        return is_governance_error

    def _process_governance_block(self, gov: GovernanceBlock, frame: Frame) -> None:
        """Process parsed governance block."""
        if gov.trace_context:
            logger.debug(
                f"Received trace context: trace_id={gov.trace_context.trace_id_hex}, "
                f"span_id={gov.trace_context.span_id_hex}"
            )

        if gov.traffic_coloring:
            logger.debug(f"Received traffic coloring: {gov.traffic_coloring.tag}")

        if gov.method_metrics:
            logger.debug(
                f"Received method metrics: queue={gov.method_metrics.queue_duration_us}us, "
                f"exec={gov.method_metrics.execution_duration_ms}ms"
            )

    def is_circuit_breaker_open(self, service_key: str) -> bool:
        """Check if circuit breaker is open for a service."""
        return service_key in self._circuit_breaker_open_services

    def get_status(self) -> dict:
        """Get interceptor status."""
        return {
            "trace_id": self._trace_id.hex() if self._trace_id else None,
            "span_id": self._span_id.hex() if self._span_id else None,
            "traffic_tag": self._traffic_tag,
            "circuit_breaker_open_services": list(self._circuit_breaker_open_services),
        }


class CompositeFrameInterceptor(FrameInterceptor):
    """Composite interceptor that chains multiple interceptors."""

    def __init__(self):
        self._interceptors: list[FrameInterceptor] = []

    def add_interceptor(self, interceptor: FrameInterceptor) -> None:
        """Add an interceptor to the chain."""
        self._interceptors.append(interceptor)

    def remove_interceptor(self, interceptor: FrameInterceptor) -> None:
        """Remove an interceptor from the chain."""
        self._interceptors.remove(interceptor)

    def on_before_send(self, frame_data: bytes, opcode: int) -> bytes:
        """Chain on_before_send calls."""
        for interceptor in self._interceptors:
            frame_data = interceptor.on_before_send(frame_data, opcode)
        return frame_data

    def on_after_receive(self, frame: Frame) -> bool:
        """Chain on_after_receive calls.

        Returns True if ANY interceptor reports a governance error.
        """
        is_error = False
        for interceptor in self._interceptors:
            if interceptor.on_after_receive(frame):
                is_error = True
        return is_error
