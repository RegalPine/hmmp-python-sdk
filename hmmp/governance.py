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

"""Governance Extension Block (TLV) parsing for HMMP protocol.

Implements Section 8 of the specification:
- Trace Context (Tag 0x01)
- Traffic Coloring (Tag 0x02)
- Method Metrics (Tag 0x03)
- Tenant Quota Token (Tag 0x04)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .constants import GovernanceTag
from .codec import BinaryReader, BinaryWriter


@dataclass
class TraceContext:
    """Distributed trace context (Tag 0x01, 24 bytes fixed)."""

    trace_id: bytes  # 16 bytes (128-bit, OpenTelemetry)
    span_id: bytes  # 8 bytes (64-bit)

    @classmethod
    def from_bytes(cls, data: bytes) -> TraceContext:
        """Parse from 24-byte TLV value."""
        if len(data) < 24:
            raise ValueError(f"TraceContext requires 24 bytes, got {len(data)}")
        return cls(
            trace_id=data[:16],
            span_id=data[16:24],
        )

    def to_bytes(self) -> bytes:
        """Serialize to 24 bytes."""
        return self.trace_id[:16].ljust(16, b"\x00") + self.span_id[:8].ljust(8, b"\x00")

    @property
    def trace_id_hex(self) -> str:
        return self.trace_id.hex()

    @property
    def span_id_hex(self) -> str:
        return self.span_id.hex()


@dataclass
class TrafficColoring:
    """Traffic coloring tag (Tag 0x02, variable max 255)."""

    tag: str  # UTF-8 routing metadata (e.g., "env=gray", "lane=canary-3")

    @classmethod
    def from_bytes(cls, data: bytes) -> TrafficColoring:
        """Parse from TLV value."""
        return cls(tag=data.decode("utf-8"))

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return self.tag.encode("utf-8")[:255]


@dataclass
class MethodMetrics:
    """Method metrics telemetry (Tag 0x03, 8 bytes fixed)."""

    queue_duration_us: int  # Bytes 0-3: queue duration in microseconds
    execution_duration_ms: int  # Bytes 4-7: execution duration in milliseconds

    @classmethod
    def from_bytes(cls, data: bytes) -> MethodMetrics:
        """Parse from 8-byte TLV value."""
        if len(data) < 8:
            raise ValueError(f"MethodMetrics requires 8 bytes, got {len(data)}")
        queue_us, exec_ms = struct.unpack("!II", data[:8])
        return cls(
            queue_duration_us=queue_us,
            execution_duration_ms=exec_ms,
        )

    def to_bytes(self) -> bytes:
        """Serialize to 8 bytes."""
        return struct.pack("!II", self.queue_duration_us, self.execution_duration_ms)


@dataclass
class TenantQuotaToken:
    """Tenant quota token (Tag 0x04, 16 bytes fixed)."""

    token: bytes  # 16 bytes tenant hash for wire-level rate limiting

    @classmethod
    def from_bytes(cls, data: bytes) -> TenantQuotaToken:
        """Parse from 16-byte TLV value."""
        if len(data) < 16:
            raise ValueError(f"TenantQuotaToken requires 16 bytes, got {len(data)}")
        return cls(token=data[:16])

    def to_bytes(self) -> bytes:
        """Serialize to 16 bytes."""
        return self.token[:16].ljust(16, b"\x00")


@dataclass
class GovernanceBlock:
    """Governance Extension Block containing TLV entries."""

    trace_context: TraceContext | None = None
    traffic_coloring: TrafficColoring | None = None
    method_metrics: MethodMetrics | None = None
    tenant_quota_token: TenantQuotaToken | None = None
    unknown_tags: dict[int, bytes] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> GovernanceBlock:
        """Parse governance block from bytes.

        Format:
        - Total Length (4 bytes, u32) - already read by frame decoder
        - TLV entries: Tag (1B) + Length (2B) + Value (variable)
        """
        block = cls()
        reader = BinaryReader(data)

        while reader.has_remaining():
            try:
                tag_type = reader.read_u8()
                tag_length = reader.read_u16()
                tag_value = reader.read_bytes(tag_length)

                if tag_type == GovernanceTag.TRACE_CONTEXT:
                    block.trace_context = TraceContext.from_bytes(tag_value)
                elif tag_type == GovernanceTag.TRAFFIC_COLORING:
                    block.traffic_coloring = TrafficColoring.from_bytes(tag_value)
                elif tag_type == GovernanceTag.METHOD_METRICS:
                    block.method_metrics = MethodMetrics.from_bytes(tag_value)
                elif tag_type == GovernanceTag.TENANT_QUOTA_TOKEN:
                    block.tenant_quota_token = TenantQuotaToken.from_bytes(tag_value)
                else:
                    block.unknown_tags[tag_type] = tag_value

            except EOFError:
                break

        return block

    def to_bytes(self) -> bytes:
        """Serialize governance block to bytes (without total length prefix)."""
        writer = BinaryWriter()

        if self.trace_context:
            value = self.trace_context.to_bytes()
            writer.write_u8(GovernanceTag.TRACE_CONTEXT)
            writer.write_u16(len(value))
            writer.write_bytes(value)

        if self.traffic_coloring:
            value = self.traffic_coloring.to_bytes()
            writer.write_u8(GovernanceTag.TRAFFIC_COLORING)
            writer.write_u16(len(value))
            writer.write_bytes(value)

        if self.method_metrics:
            value = self.method_metrics.to_bytes()
            writer.write_u8(GovernanceTag.METHOD_METRICS)
            writer.write_u16(len(value))
            writer.write_bytes(value)

        if self.tenant_quota_token:
            value = self.tenant_quota_token.to_bytes()
            writer.write_u8(GovernanceTag.TENANT_QUOTA_TOKEN)
            writer.write_u16(len(value))
            writer.write_bytes(value)

        for tag_type, tag_value in self.unknown_tags.items():
            writer.write_u8(tag_type)
            writer.write_u16(len(tag_value))
            writer.write_bytes(tag_value)

        return writer.getvalue()

    def to_frame_bytes(self) -> bytes:
        """Serialize with total length prefix for frame inclusion."""
        content = self.to_bytes()
        return struct.pack("!I", len(content)) + content

    def is_empty(self) -> bool:
        """Check if governance block has any content."""
        return (
            self.trace_context is None
            and self.traffic_coloring is None
            and self.method_metrics is None
            and self.tenant_quota_token is None
            and not self.unknown_tags
        )


def parse_governance_block(data: bytes) -> GovernanceBlock:
    """Parse governance extension block from frame data.

    Args:
        data: Governance block bytes (after the 4-byte length prefix)

    Returns:
        Parsed GovernanceBlock
    """
    return GovernanceBlock.from_bytes(data)


def build_governance_block(
    trace_id: bytes | None = None,
    span_id: bytes | None = None,
    traffic_tag: str | None = None,
    queue_duration_us: int | None = None,
    execution_duration_ms: int | None = None,
    quota_token: bytes | None = None,
) -> bytes | None:
    """Build a governance block for outgoing frames.

    Args:
        trace_id: 16-byte trace ID
        span_id: 8-byte span ID
        traffic_tag: Traffic coloring tag string
        queue_duration_us: Queue duration in microseconds
        execution_duration_ms: Execution duration in milliseconds
        quota_token: 16-byte tenant quota token

    Returns:
        Serialized governance block bytes (with length prefix), or None if empty
    """
    block = GovernanceBlock()

    if trace_id and span_id:
        block.trace_context = TraceContext(trace_id=trace_id, span_id=span_id)

    if traffic_tag:
        block.traffic_coloring = TrafficColoring(tag=traffic_tag)

    if queue_duration_us is not None and execution_duration_ms is not None:
        block.method_metrics = MethodMetrics(
            queue_duration_us=queue_duration_us,
            execution_duration_ms=execution_duration_ms,
        )

    if quota_token:
        block.tenant_quota_token = TenantQuotaToken(token=quota_token)

    if block.is_empty():
        return None

    return block.to_frame_bytes()
