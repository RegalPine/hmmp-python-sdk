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

"""Data models for HMMP protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .codec import BinaryReader, BinaryWriter, ip_to_bytes, bytes_to_ip
from .constants import IpType, AddressFamily


@dataclass
class ServiceInstance:
    """A registered service instance."""

    service_name: str
    ip: str
    port: int
    weight: float = 1.0
    ephemeral: bool = True
    healthy: bool = True
    metadata: dict[str, str] = field(default_factory=dict)
    metadata_hash: int = 0
    metrics_pack: int = 0

    @property
    def ip_type(self) -> IpType:
        _, ip_type = ip_to_bytes(self.ip)
        return ip_type

    def to_register_bytes(self) -> bytes:
        """Serialize to RegisterInstanceRequest body (0x0101)."""
        writer = BinaryWriter()
        writer.write_string_u16(self.service_name)

        ip_bytes, ip_type = ip_to_bytes(self.ip)
        writer.write_u8(ip_type)
        writer.write_u16(self.port)
        writer.write_u8(1 if self.ephemeral else 0)
        writer.write_bytes(ip_bytes)
        writer.write_f32(self.weight)

        return writer.getvalue()

    def to_register_with_meta_bytes(self) -> bytes:
        """Serialize to RegisterInstanceWithMetaRequest body (0x0109)."""
        writer = BinaryWriter()
        writer.write_string_u16(self.service_name)

        ip_bytes, ip_type = ip_to_bytes(self.ip)
        writer.write_u8(ip_type)
        writer.write_u16(self.port)
        writer.write_u8(1 if self.ephemeral else 0)
        writer.write_bytes(ip_bytes)
        writer.write_f32(self.weight)

        # Metadata
        writer.write_u16(len(self.metadata))
        for key, value in self.metadata.items():
            writer.write_string_u8(key)
            writer.write_string_u16(value)

        return writer.getvalue()

    def to_deregister_bytes(self) -> bytes:
        """Serialize to DeregisterInstanceRequest body (0x0103)."""
        writer = BinaryWriter()
        writer.write_string_u16(self.service_name)

        ip_bytes, ip_type = ip_to_bytes(self.ip)
        addr_family = AddressFamily.IPV4 if ip_type == IpType.IPV4 else AddressFamily.IPV6
        writer.write_u16(addr_family)
        writer.write_bytes(ip_bytes)
        writer.write_u16(self.port)

        return writer.getvalue()

    @classmethod
    def from_snapshot_bytes(cls, reader: BinaryReader, service_name: str) -> ServiceInstance:
        """Parse from snapshot instance array item."""
        ip_type = IpType(reader.read_u8())
        port = reader.read_u16()
        is_healthy = reader.read_u8() == 1
        ip_bytes = reader.read_ip(ip_type)
        weight = reader.read_f32()
        metrics_pack = reader.read_u32()
        metadata_hash = reader.read_u64()

        return cls(
            service_name=service_name,
            ip=bytes_to_ip(ip_bytes, ip_type),
            port=port,
            weight=weight,
            healthy=is_healthy,
            metrics_pack=metrics_pack,
            metadata_hash=metadata_hash,
        )


@dataclass
class ServiceSnapshot:
    """Service discovery snapshot."""

    service_name: str
    topology_version: int
    instances: list[ServiceInstance] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> ServiceSnapshot:
        """Parse from DiscoverServiceResponse/ServiceChangedNotify body."""
        reader = BinaryReader(data)
        service_name = reader.read_string_u16()
        topology_version = reader.read_u64()
        instance_count = reader.read_u16()

        instances = []
        for _ in range(instance_count):
            instances.append(ServiceInstance.from_snapshot_bytes(reader, service_name))

        return cls(
            service_name=service_name,
            topology_version=topology_version,
            instances=instances,
        )


@dataclass
class FilteredServiceSnapshot:
    """Filtered service discovery snapshot."""

    service_name: str
    topology_version: int
    total_count: int
    instances: list[ServiceInstance] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes, include_metadata: bool = False) -> FilteredServiceSnapshot:
        """Parse from DiscoverServiceByFilterResponse body."""
        reader = BinaryReader(data)
        service_name = reader.read_string_u16()
        topology_version = reader.read_u64()
        total_count = reader.read_u16()
        instance_count = reader.read_u16()

        instances = []
        for _ in range(instance_count):
            instance = ServiceInstance.from_snapshot_bytes(reader, service_name)
            if include_metadata:
                meta_count = reader.read_u16()
                for _ in range(meta_count):
                    key = reader.read_string_u8()
                    value = reader.read_string_u16()
                    instance.metadata[key] = value
            instances.append(instance)

        return cls(
            service_name=service_name,
            topology_version=topology_version,
            total_count=total_count,
            instances=instances,
        )


@dataclass
class ConfigEntry:
    """Configuration entry."""

    tenant: str
    group: str
    data_id: str
    content: bytes = b""
    md5: bytes = b""
    is_deleted: bool = False
    total_chunks: int = 1
    chunk_index: int = 0
    # Canary fields
    version_id: str = ""
    stable_version_id: str = ""
    match_labels: dict[str, str] = field(default_factory=dict)

    @property
    def content_str(self) -> str:
        """Get content as UTF-8 string."""
        return self.content.decode("utf-8")

    def to_get_request_bytes(self, canary_labels: dict[str, str] | None = None) -> bytes:
        """Serialize to GetConfigRequest body (0x0201)."""
        writer = BinaryWriter()
        writer.write_string_u8(self.tenant)
        writer.write_string_u8(self.group)
        writer.write_string_u8(self.data_id)

        # Canary context
        if canary_labels:
            writer.write_u8(1)  # has_canary
            writer.write_u8(len(canary_labels))
            for key, value in canary_labels.items():
                writer.write_string_u8(key)
                writer.write_string_u8(value)
        else:
            writer.write_u8(0)  # no canary

        return writer.getvalue()

    @classmethod
    def from_response_bytes(cls, data: bytes) -> ConfigEntry:
        """Parse from ConfigResponse body (0x0202)."""
        reader = BinaryReader(data)
        tenant = reader.read_string_u8()
        group = reader.read_string_u8()
        data_id = reader.read_string_u8()
        md5 = reader.read_bytes(16)
        total_chunks = reader.read_u16()
        chunk_index = reader.read_u16()
        is_deleted = reader.read_u8() == 1

        # Read raw_bytes length and content
        raw_len = reader.read_u32()
        raw_bytes = reader.read_bytes(raw_len)

        entry = cls(
            tenant=tenant,
            group=group,
            data_id=data_id,
            md5=md5,
            total_chunks=total_chunks,
            chunk_index=chunk_index,
            is_deleted=is_deleted,
            content=raw_bytes,
        )

        # Parse canary context if present
        if reader.has_remaining():
            has_canary = reader.read_u8()
            if has_canary == 1:
                entry.version_id = reader.read_string_u16()
                entry.stable_version_id = reader.read_string_u16()
                match_count = reader.read_u8()
                for _ in range(match_count):
                    key = reader.read_string_u8()
                    value = reader.read_string_u8()
                    entry.match_labels[key] = value

        return entry


@dataclass
class ListenConfigEntry:
    """Configuration listen entry."""

    tenant: str
    group: str
    data_id: str
    current_md5: bytes = b"\x00" * 16

    def to_bytes(self) -> bytes:
        """Serialize for ListenConfigRequest."""
        writer = BinaryWriter()
        writer.write_string_u8(self.tenant)
        writer.write_string_u8(self.group)
        writer.write_string_u8(self.data_id)
        writer.write_bytes(self.current_md5)
        return writer.getvalue()


@dataclass
class ConfigChangedNotification:
    """Configuration changed notification."""

    tenant: str
    group: str
    data_id: str
    new_md5: bytes
    # Canary fields
    version_id: str = ""
    changed_reason: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> ConfigChangedNotification:
        """Parse from ConfigChangedNotify body (0x0204)."""
        reader = BinaryReader(data)
        tenant = reader.read_string_u16()
        group = reader.read_string_u16()
        data_id = reader.read_string_u16()
        new_md5 = reader.read_bytes(16)

        notification = cls(
            tenant=tenant,
            group=group,
            data_id=data_id,
            new_md5=new_md5,
        )

        # Parse canary context if present
        if reader.has_remaining():
            has_canary = reader.read_u8()
            if has_canary == 1:
                notification.version_id = reader.read_string_u16()
                notification.changed_reason = reader.read_u8()

        return notification


@dataclass
class HandshakeResult:
    """Handshake response data."""

    session_id: str
    status: int
    config_cipher_suite: str = ""
    config_key_id: str = ""
    config_key_rotation_ms: int = 0
    canary_enabled: bool = False
    canary_match_result: dict[str, str] = field(default_factory=dict)


@dataclass
class NonceChallengeResult:
    """Nonce challenge response data."""

    status: int
    server_nonce: bytes = b""
    nonce_ttl_ms: int = 0
    server_timestamp: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> NonceChallengeResult:
        """Parse from NonceChallengeResponse body (0x0008)."""
        reader = BinaryReader(data)
        status = reader.read_u16()
        server_nonce = reader.read_bytes(32)
        nonce_ttl_ms = reader.read_u32()
        server_timestamp = reader.read_u64()

        return cls(
            status=status,
            server_nonce=server_nonce,
            nonce_ttl_ms=nonce_ttl_ms,
            server_timestamp=server_timestamp,
        )


@dataclass
class RedirectInfo:
    """Connection redirect information."""

    sequence_number: int
    reason: int
    graceful_wait_ms: int
    target_ip: str
    target_port: int

    @classmethod
    def from_bytes(cls, data: bytes) -> RedirectInfo:
        """Parse from ClusterNodeRedirectNotify body (0x0005)."""
        reader = BinaryReader(data)
        sequence_number = reader.read_u32()
        reason = reader.read_u8()
        graceful_wait_ms = reader.read_u16()
        target_ip_type = IpType(reader.read_u8())
        target_port = reader.read_u16()
        target_ip_bytes = reader.read_ip(target_ip_type)

        return cls(
            sequence_number=sequence_number,
            reason=reason,
            graceful_wait_ms=graceful_wait_ms,
            target_ip=bytes_to_ip(target_ip_bytes, target_ip_type),
            target_port=target_port,
        )


@dataclass
class ShutdownNotice:
    """Instance shutdown prepare notice."""

    shutdown_delay_ms: int

    @classmethod
    def from_bytes(cls, data: bytes) -> ShutdownNotice:
        """Parse from InstanceShutdownPrepareNotice body (0x0006)."""
        reader = BinaryReader(data)
        return cls(shutdown_delay_ms=reader.read_u32())


@dataclass
class TenantStats:
    """Tenant statistics."""

    found: bool
    active_connections: int
    registered_services: int
    registered_instances: int
    credential_count: int
    config_count: int

    @classmethod
    def from_bytes(cls, data: bytes) -> TenantStats:
        """Parse from AdminGetTenantStatsRes body (0x0418)."""
        reader = BinaryReader(data)
        return cls(
            found=reader.read_u8() == 1,
            active_connections=reader.read_u32(),
            registered_services=reader.read_u16(),
            registered_instances=reader.read_u32(),
            credential_count=reader.read_u16(),
            config_count=reader.read_u32(),
        )


@dataclass
class CredentialInfo:
    """Credential information (without secret)."""

    client_id: str
    tenant: str
    node_type: str
    enabled: bool
    created_at: int


@dataclass
class FilterExpression:
    """Filter expression for service discovery."""

    node_type: int  # FilterNodeType
    # For LEAF nodes
    key: str = ""
    operator: int = 0  # FilterOperator
    operand: str = ""
    # For combinator nodes
    children: list[FilterExpression] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize filter expression to binary format."""
        from .constants import FilterNodeType

        writer = BinaryWriter()
        writer.write_u8(self.node_type)

        if self.node_type == FilterNodeType.LEAF:
            writer.write_string_u8(self.key)
            writer.write_u8(self.operator)
            writer.write_string_u16(self.operand)
        elif self.node_type in (FilterNodeType.AND, FilterNodeType.OR):
            writer.write_u8(len(self.children))
            for child in self.children:
                writer.write_bytes(child.to_bytes())
        elif self.node_type == FilterNodeType.NOT:
            if self.children:
                writer.write_bytes(self.children[0].to_bytes())

        return writer.getvalue()

    @staticmethod
    def leaf(key: str, operator: int, operand: str = "") -> FilterExpression:
        """Create a leaf predicate."""
        from .constants import FilterNodeType
        return FilterExpression(
            node_type=FilterNodeType.LEAF,
            key=key,
            operator=operator,
            operand=operand,
        )

    @staticmethod
    def and_(*children: FilterExpression) -> FilterExpression:
        """Create an AND combinator."""
        from .constants import FilterNodeType
        return FilterExpression(
            node_type=FilterNodeType.AND,
            children=list(children),
        )

    @staticmethod
    def or_(*children: FilterExpression) -> FilterExpression:
        """Create an OR combinator."""
        from .constants import FilterNodeType
        return FilterExpression(
            node_type=FilterNodeType.OR,
            children=list(children),
        )

    @staticmethod
    def not_(child: FilterExpression) -> FilterExpression:
        """Create a NOT combinator."""
        from .constants import FilterNodeType
        return FilterExpression(
            node_type=FilterNodeType.NOT,
            children=[child],
        )
