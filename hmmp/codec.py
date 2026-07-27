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

"""Binary serialization/deserialization utilities for HMMP protocol."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import Any

from .constants import FNV_OFFSET_BASIS, FNV_PRIME, IpType


class BinaryWriter:
    """Binary data writer for HMMP protocol encoding."""

    def __init__(self) -> None:
        self._buffer = BytesIO()

    def write_u8(self, value: int) -> BinaryWriter:
        """Write unsigned 8-bit integer."""
        self._buffer.write(struct.pack("!B", value & 0xFF))
        return self

    def write_u16(self, value: int) -> BinaryWriter:
        """Write unsigned 16-bit integer (big-endian)."""
        self._buffer.write(struct.pack("!H", value & 0xFFFF))
        return self

    def write_u32(self, value: int) -> BinaryWriter:
        """Write unsigned 32-bit integer (big-endian)."""
        self._buffer.write(struct.pack("!I", value & 0xFFFFFFFF))
        return self

    def write_u64(self, value: int) -> BinaryWriter:
        """Write unsigned 64-bit integer (big-endian)."""
        self._buffer.write(struct.pack("!Q", value & 0xFFFFFFFFFFFFFFFF))
        return self

    def write_f32(self, value: float) -> BinaryWriter:
        """Write 32-bit IEEE 754 float (big-endian)."""
        self._buffer.write(struct.pack("!f", value))
        return self

    def write_bytes(self, data: bytes) -> BinaryWriter:
        """Write raw bytes."""
        self._buffer.write(data)
        return self

    def write_string_u8(self, value: str) -> BinaryWriter:
        """Write string with u8 length prefix."""
        encoded = value.encode("utf-8")
        self.write_u8(len(encoded))
        self._buffer.write(encoded)
        return self

    def write_string_u16(self, value: str) -> BinaryWriter:
        """Write string with u16 length prefix."""
        encoded = value.encode("utf-8")
        self.write_u16(len(encoded))
        self._buffer.write(encoded)
        return self

    def write_ip(self, ip_bytes: bytes, ip_type: IpType) -> BinaryWriter:
        """Write IP address (4 bytes for IPv4, 16 bytes for IPv6)."""
        expected_len = 4 if ip_type == IpType.IPV4 else 16
        if len(ip_bytes) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes for {ip_type.name}")
        self._buffer.write(ip_bytes)
        return self

    def getvalue(self) -> bytes:
        """Get the written bytes."""
        return self._buffer.getvalue()

    def __len__(self) -> int:
        return self._buffer.tell()


class BinaryReader:
    """Binary data reader for HMMP protocol decoding."""

    def __init__(self, data: bytes) -> None:
        self._buffer = BytesIO(data)
        self._data = data

    def read_u8(self) -> int:
        """Read unsigned 8-bit integer."""
        data = self._buffer.read(1)
        if len(data) < 1:
            raise EOFError("Unexpected end of data reading u8")
        return struct.unpack("!B", data)[0]

    def read_u16(self) -> int:
        """Read unsigned 16-bit integer (big-endian)."""
        data = self._buffer.read(2)
        if len(data) < 2:
            raise EOFError("Unexpected end of data reading u16")
        return struct.unpack("!H", data)[0]

    def read_u32(self) -> int:
        """Read unsigned 32-bit integer (big-endian)."""
        data = self._buffer.read(4)
        if len(data) < 4:
            raise EOFError("Unexpected end of data reading u32")
        return struct.unpack("!I", data)[0]

    def read_u64(self) -> int:
        """Read unsigned 64-bit integer (big-endian)."""
        data = self._buffer.read(8)
        if len(data) < 8:
            raise EOFError("Unexpected end of data reading u64")
        return struct.unpack("!Q", data)[0]

    def read_f32(self) -> float:
        """Read 32-bit IEEE 754 float (big-endian)."""
        data = self._buffer.read(4)
        if len(data) < 4:
            raise EOFError("Unexpected end of data reading f32")
        return struct.unpack("!f", data)[0]

    def read_bytes(self, length: int) -> bytes:
        """Read exact number of bytes."""
        data = self._buffer.read(length)
        if len(data) < length:
            raise EOFError(f"Unexpected end of data: expected {length}, got {len(data)}")
        return data

    def read_string_u8(self) -> str:
        """Read string with u8 length prefix."""
        length = self.read_u8()
        data = self.read_bytes(length)
        return data.decode("utf-8")

    def read_string_u16(self) -> str:
        """Read string with u16 length prefix."""
        length = self.read_u16()
        data = self.read_bytes(length)
        return data.decode("utf-8")

    def read_ip(self, ip_type: IpType) -> bytes:
        """Read IP address based on type."""
        length = 4 if ip_type == IpType.IPV4 else 16
        return self.read_bytes(length)

    def remaining(self) -> int:
        """Get remaining bytes count."""
        current = self._buffer.tell()
        return len(self._data) - current

    def has_remaining(self) -> bool:
        """Check if there are remaining bytes."""
        return self.remaining() > 0

    @property
    def position(self) -> int:
        """Current read position."""
        return self._buffer.tell()


def ip_to_bytes(ip: str) -> tuple[bytes, IpType]:
    """Convert IP string to bytes and determine type."""
    import ipaddress

    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.packed, IpType.IPV4
    except ipaddress.AddressValueError:
        pass

    try:
        addr = ipaddress.IPv6Address(ip)
        return addr.packed, IpType.IPV6
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IP address: {ip}")


def bytes_to_ip(data: bytes, ip_type: IpType) -> str:
    """Convert bytes to IP string."""
    import ipaddress

    if ip_type == IpType.IPV4:
        return str(ipaddress.IPv4Address(data))
    else:
        return str(ipaddress.IPv6Address(data))


def fnv1a_64(data: bytes) -> int:
    """Compute FNV-1a 64-bit hash."""
    hash_value = FNV_OFFSET_BASIS
    for byte in data:
        hash_value ^= byte
        hash_value = (hash_value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return hash_value


def compute_metadata_hash(metadata: dict[str, str]) -> int:
    """Compute canonical metadata hash per spec Section 6.6.3.

    1. Sort entries by key in ascending byte-wise order
    2. Concatenate: key_bytes || 0x00 || value_bytes || 0x00
    3. Compute FNV-1a 64-bit hash
    4. Empty metadata returns 0
    """
    if not metadata:
        return 0

    sorted_keys = sorted(metadata.keys(), key=lambda k: k.encode("utf-8"))
    concatenated = bytearray()
    for key in sorted_keys:
        concatenated.extend(key.encode("utf-8"))
        concatenated.append(0x00)
        concatenated.extend(metadata[key].encode("utf-8"))
        concatenated.append(0x00)

    return fnv1a_64(bytes(concatenated))


def pack_metrics_pack(
    cpu: int = 0,
    memory: int = 0,
    active_conns: int = 0,
    ewma_delay: int = 0,
    error: bool = False,
    preheating: bool = False,
    delay_scale: bool = False,
) -> int:
    """Pack metrics into 32-bit metrics_pack format (Section 9.5).

    Bits 0-4: CPU (0-31, ×3.22 = percentage)
    Bits 5-9: Memory (0-31, ×3.22 = percentage)
    Bits 10-19: Active Conns (0-1023)
    Bits 20-28: EWMA Delay (0-511)
    Bit 29: Error flag
    Bit 30: Pre-heating flag
    Bit 31: Delay scale (0=1ms, 1=10ms)
    """
    pack = 0
    pack |= (cpu & 0x1F)
    pack |= (memory & 0x1F) << 5
    pack |= (active_conns & 0x3FF) << 10
    pack |= (ewma_delay & 0x1FF) << 20
    if error:
        pack |= 1 << 29
    if preheating:
        pack |= 1 << 30
    if delay_scale:
        pack |= 1 << 31
    return pack


def unpack_metrics_pack(pack: int) -> dict[str, Any]:
    """Unpack 32-bit metrics_pack into components."""
    return {
        "cpu": pack & 0x1F,
        "cpu_percent": (pack & 0x1F) * 3.22,
        "memory": (pack >> 5) & 0x1F,
        "memory_percent": ((pack >> 5) & 0x1F) * 3.22,
        "active_conns": (pack >> 10) & 0x3FF,
        "ewma_delay": (pack >> 20) & 0x1FF,
        "error": bool((pack >> 29) & 1),
        "preheating": bool((pack >> 30) & 1),
        "delay_scale": bool((pack >> 31) & 1),
    }
