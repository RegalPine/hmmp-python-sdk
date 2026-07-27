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

"""HMMP frame encoding and decoding.

Frame structure:
- 16-byte fixed header
- Optional governance extension block (if FLAG_GOVERNANCE set)
- Two-tier payload: metadata_length (2B) + metadata (MessagePack) + body (binary)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

import msgpack

from .constants import (
    HEADER_SIZE,
    MAGIC_NUMBER,
    PROTOCOL_VERSION,
    Flag,
    OpCode,
)
from .exceptions import ProtocolError


@dataclass
class FrameHeader:
    """HMMP frame header (16 bytes fixed)."""

    magic: int = MAGIC_NUMBER
    version: int = PROTOCOL_VERSION
    flags: int = 0
    stream_id: int = 0
    payload_length: int = 0
    padding: int = 0

    def to_bytes(self) -> bytes:
        """Serialize header to 16 bytes."""
        return struct.pack(
            "!HBBIII",
            self.magic,
            self.version,
            self.flags,
            self.stream_id,
            self.payload_length,
            self.padding,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> FrameHeader:
        """Parse header from 16 bytes."""
        if len(data) < HEADER_SIZE:
            raise ProtocolError(f"Header too short: {len(data)} < {HEADER_SIZE}")

        magic, version, flags, stream_id, payload_length, padding = struct.unpack(
            "!HBBIII", data[:HEADER_SIZE]
        )

        if magic != MAGIC_NUMBER:
            raise ProtocolError(f"Invalid magic number: 0x{magic:04X}")

        return cls(
            magic=magic,
            version=version,
            flags=flags,
            stream_id=stream_id,
            payload_length=payload_length,
            padding=padding,
        )

    @property
    def is_request(self) -> bool:
        return bool(self.flags & Flag.REQUEST)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & Flag.COMPRESSION)

    @property
    def has_backpressure(self) -> bool:
        return bool(self.flags & Flag.BACKPRESSURE)

    @property
    def is_redirect(self) -> bool:
        return bool(self.flags & Flag.REDIRECT)

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & Flag.ENCRYPTED)

    @property
    def is_probing(self) -> bool:
        return bool(self.flags & Flag.PROBING)

    @property
    def has_governance(self) -> bool:
        return bool(self.flags & Flag.GOVERNANCE)


@dataclass
class Frame:
    """Complete HMMP frame with header, metadata, and body."""

    header: FrameHeader
    metadata: dict[str, Any] = field(default_factory=dict)
    body: bytes = b""
    governance_block: bytes | None = None

    @property
    def stream_id(self) -> int:
        return self.header.stream_id

    @property
    def body_type(self) -> int | None:
        """Get the OpCode from metadata body_type."""
        return self.metadata.get("body_type")

    @property
    def opcode(self) -> OpCode | None:
        """Get OpCode enum from body_type."""
        bt = self.body_type
        if bt is not None:
            try:
                return OpCode(bt)
            except ValueError:
                return None
        return None

    @property
    def trace_id(self) -> str | None:
        return self.metadata.get("trace_id")

    @property
    def token(self) -> str | None:
        return self.metadata.get("token")


class FrameEncoder:
    """Encodes HMMP frames to bytes."""

    def __init__(self, client_version: str = "hmmp-python/0.7.0"):
        self.client_version = client_version

    def encode(
        self,
        opcode: OpCode,
        body: bytes = b"",
        stream_id: int = 0,
        is_request: bool = True,
        metadata: dict[str, Any] | None = None,
        flags: int = 0,
        governance_block: bytes | None = None,
    ) -> bytes:
        """Encode a complete frame to bytes.

        Args:
            opcode: The operation code (body_type)
            body: Binary body payload
            stream_id: Stream identifier
            is_request: Whether this is a request frame
            metadata: Additional metadata (merged with defaults)
            flags: Additional flags to set
            governance_block: Optional governance TLV block
        """
        # Build metadata
        meta = {
            "body_type": int(opcode),
            "client_version": self.client_version,
        }
        if metadata:
            meta.update(metadata)

        # Serialize metadata with MessagePack
        meta_bytes = msgpack.packb(meta, use_bin_type=True)

        # Build payload: metadata_length (2B) + metadata + body
        payload = struct.pack("!H", len(meta_bytes)) + meta_bytes + body

        # Set flags
        frame_flags = flags
        if is_request:
            frame_flags |= Flag.REQUEST
        if governance_block:
            frame_flags |= Flag.GOVERNANCE

        # Build header
        header = FrameHeader(
            magic=MAGIC_NUMBER,
            version=PROTOCOL_VERSION,
            flags=frame_flags,
            stream_id=stream_id,
            payload_length=len(payload) + (len(governance_block) + 4 if governance_block else 0),
            padding=0,
        )

        # Assemble frame
        result = header.to_bytes()
        if governance_block:
            result += struct.pack("!I", len(governance_block))
            result += governance_block
        result += payload

        return result


class FrameDecoder:
    """Decodes bytes to HMMP frames."""

    def decode_header(self, data: bytes) -> FrameHeader:
        """Decode just the header from bytes."""
        return FrameHeader.from_bytes(data)

    def decode(self, data: bytes) -> Frame:
        """Decode a complete frame from bytes.

        Args:
            data: Complete frame bytes (header + payload)

        Returns:
            Decoded Frame object
        """
        if len(data) < HEADER_SIZE:
            raise ProtocolError(f"Data too short for header: {len(data)}")

        header = FrameHeader.from_bytes(data)
        offset = HEADER_SIZE

        governance_block = None
        if header.has_governance:
            if len(data) < offset + 4:
                raise ProtocolError("Data too short for governance length")
            gov_len = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4
            if len(data) < offset + gov_len:
                raise ProtocolError("Data too short for governance block")
            governance_block = data[offset:offset + gov_len]
            offset += gov_len

        # Parse payload
        payload_start = offset
        if len(data) < payload_start + 2:
            raise ProtocolError("Data too short for metadata length")

        meta_len = struct.unpack("!H", data[payload_start:payload_start + 2])[0]
        payload_start += 2

        if len(data) < payload_start + meta_len:
            raise ProtocolError("Data too short for metadata")

        meta_bytes = data[payload_start:payload_start + meta_len]
        payload_start += meta_len

        try:
            metadata = msgpack.unpackb(meta_bytes, raw=False)
        except Exception as e:
            raise ProtocolError(f"Failed to decode metadata: {e}")

        body = data[payload_start:]

        return Frame(
            header=header,
            metadata=metadata,
            body=body,
            governance_block=governance_block,
        )

    def decode_payload(self, payload: bytes) -> tuple[dict[str, Any], bytes]:
        """Decode just the payload portion (metadata + body).

        Returns:
            Tuple of (metadata dict, body bytes)
        """
        if len(payload) < 2:
            raise ProtocolError("Payload too short")

        meta_len = struct.unpack("!H", payload[:2])[0]
        if len(payload) < 2 + meta_len:
            raise ProtocolError("Payload too short for metadata")

        meta_bytes = payload[2:2 + meta_len]
        body = payload[2 + meta_len:]

        try:
            metadata = msgpack.unpackb(meta_bytes, raw=False)
        except Exception as e:
            raise ProtocolError(f"Failed to decode metadata: {e}")

        return metadata, body
