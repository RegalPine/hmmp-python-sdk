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

"""Admin management service for HMMP protocol.

Provides management plane operations (OpCodes 0x0400-0x04FF):
- Tenant lifecycle (create/update/delete/stats)
- Credential lifecycle (CRUD)
- Config management (list/put/delete)
- Service listing
- Governance state query
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .codec import BinaryReader, BinaryWriter
from .constants import OpCode, StatusCode
from .models import CredentialInfo, TenantStats

if TYPE_CHECKING:
    from .client import HMMPClient

logger = logging.getLogger(__name__)


@dataclass
class AdminConfigItem:
    """Configuration item from admin list."""
    tenant: str
    group: str
    data_id: str
    md5: bytes
    length: int
    deleted: bool


@dataclass
class AdminTenantItem:
    """Tenant item from admin list."""
    tenant: str
    max_connections: int
    rate_limit_ops: int
    policy_flags: int


@dataclass
class TenantPolicy:
    """Tenant policy details."""
    tenant: str
    policy_flags: int
    max_connections: int
    rate_limit_ops: int
    lease_duration_ms: int


@dataclass
class GovernanceState:
    """Governance state from server."""
    circuit_breakers: list[dict]
    coloring_rules: list[dict]
    outlier_votes: list[dict]


class AdminService:
    """Admin management service for HMMP management plane operations.

    All operations require the connection to be authenticated with
    node_type = "admin_console".
    """

    def __init__(self, client: HMMPClient):
        self._client = client

    # ---- Tenant Lifecycle ----

    async def create_tenant(
        self,
        tenant: str,
        policy_flags: int = 0,
        max_connections: int = 0,
        rate_limit_ops: int = 0,
        lease_duration_ms: int = 0,
    ) -> int:
        """Create a new tenant (OpCode 0x0411).

        Args:
            tenant: Tenant name (1-128 chars, alphanumeric + -_.)
            policy_flags: Bit 0: READ_ONLY; Bit 1: EPHEMERAL_ENFORCE
            max_connections: Max concurrent connections (0 = unlimited)
            rate_limit_ops: Operations-per-second quota (0 = unlimited)
            lease_duration_ms: Lease lifetime in ms (0 = never expires)

        Returns:
            Status code (0x0000 = success)
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_u16(policy_flags)
        writer.write_u32(max_connections)
        writer.write_u32(rate_limit_ops)
        writer.write_u64(lease_duration_ms)

        response = await self._client._send_request(
            OpCode.ADMIN_CREATE_TENANT_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        status = reader.read_u16()

        if status == StatusCode.OK:
            logger.info(f"Tenant created: {tenant}")
        else:
            logger.warning(f"Create tenant failed: {tenant}, status={status}")

        return status

    async def update_tenant_policy(
        self,
        tenant: str,
        policy_flags: int = 0,
        max_connections: int = 0,
        rate_limit_ops: int = 0,
        lease_duration_ms: int = 0,
    ) -> int:
        """Update tenant policy (OpCode 0x0413).

        PUT semantics: does NOT create the tenant if absent.

        Returns:
            Status code (0x0000 = success, 1407 = not found)
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_u16(policy_flags)
        writer.write_u32(max_connections)
        writer.write_u32(rate_limit_ops)
        writer.write_u64(lease_duration_ms)

        response = await self._client._send_request(
            OpCode.ADMIN_UPDATE_TENANT_POLICY_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        return reader.read_u16()

    async def delete_tenant(self, tenant: str, force: bool = False) -> int:
        """Delete a tenant (OpCode 0x0415).

        Args:
            tenant: Tenant name
            force: False = safe deletion (fail if not empty);
                   True = force cascade deletion

        Returns:
            Status code (0x0000 = success, 1405 = not empty, 1407 = not found)
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_u8(1 if force else 0)

        response = await self._client._send_request(
            OpCode.ADMIN_DELETE_TENANT_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        status = reader.read_u16()

        if status == StatusCode.OK:
            logger.info(f"Tenant deleted: {tenant} (force={force})")

        return status

    async def get_tenant_stats(self, tenant: str) -> TenantStats:
        """Get tenant statistics (OpCode 0x0417).

        Returns:
            TenantStats object with connection/instance/config counts
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)

        response = await self._client._send_request(
            OpCode.ADMIN_GET_TENANT_STATS_REQ, writer.getvalue()
        )
        return TenantStats.from_bytes(response.body)

    # ---- Credential Lifecycle ----

    async def create_credential(
        self,
        client_id: str,
        secret: str,
        tenant: str,
        node_type: str = "client",
    ) -> int:
        """Create a credential (OpCode 0x0419).

        Args:
            client_id: Client identifier (1-128 chars)
            secret: Secret key (1-256 chars)
            tenant: Tenant name (or "*" for wildcard)
            node_type: One of "client", "admin_console", "cluster_peer"

        Returns:
            Status code (0x0000 = success, 1408 = already exists)
        """
        writer = BinaryWriter()
        writer.write_string_u16(client_id)
        writer.write_string_u16(secret)
        writer.write_string_u16(tenant)
        writer.write_string_u16(node_type)

        response = await self._client._send_request(
            OpCode.ADMIN_CREATE_CREDENTIAL_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        status = reader.read_u16()

        if status == StatusCode.OK:
            logger.info(f"Credential created: {client_id}")

        return status

    async def update_credential(
        self,
        client_id: str,
        secret: str | None = None,
        tenant: str | None = None,
        node_type: str | None = None,
        enabled: bool | None = None,
    ) -> int:
        """Update a credential (OpCode 0x041B).

        Only fields with non-None values are applied.

        Returns:
            Status code (0x0000 = success, 1409 = not found)
        """
        writer = BinaryWriter()
        writer.write_string_u16(client_id)

        # has_secret
        if secret is not None:
            writer.write_u8(1)
            writer.write_string_u16(secret)
        else:
            writer.write_u8(0)

        # has_tenant
        if tenant is not None:
            writer.write_u8(1)
            writer.write_string_u16(tenant)
        else:
            writer.write_u8(0)

        # has_node_type
        if node_type is not None:
            writer.write_u8(1)
            writer.write_string_u16(node_type)
        else:
            writer.write_u8(0)

        # has_enabled
        if enabled is not None:
            writer.write_u8(1)
            writer.write_u8(1 if enabled else 0)
        else:
            writer.write_u8(0)

        response = await self._client._send_request(
            OpCode.ADMIN_UPDATE_CREDENTIAL_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        return reader.read_u16()

    async def delete_credential(self, client_id: str) -> int:
        """Delete a credential (OpCode 0x041D).

        Returns:
            Status code (0x0000 = success, 1409 = not found)
        """
        writer = BinaryWriter()
        writer.write_string_u16(client_id)

        response = await self._client._send_request(
            OpCode.ADMIN_DELETE_CREDENTIAL_REQ, writer.getvalue()
        )
        reader = BinaryReader(response.body)
        status = reader.read_u16()

        if status == StatusCode.OK:
            logger.info(f"Credential deleted: {client_id}")

        return status

    async def list_credentials(self, tenant_filter: str = "") -> list[CredentialInfo]:
        """List credentials (OpCode 0x041F).

        Args:
            tenant_filter: Filter by tenant (empty = all tenants)

        Returns:
            List of CredentialInfo (secrets are NEVER included)
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant_filter)

        response = await self._client._send_request(
            OpCode.ADMIN_LIST_CREDENTIALS_REQ, writer.getvalue()
        )

        reader = BinaryReader(response.body)
        count = reader.read_u16()

        credentials = []
        for _ in range(count):
            client_id = reader.read_string_u16()
            tenant = reader.read_string_u16()
            node_type = reader.read_string_u16()
            enabled = reader.read_u8() == 1
            created_at = reader.read_u64()

            credentials.append(CredentialInfo(
                client_id=client_id,
                tenant=tenant,
                node_type=node_type,
                enabled=enabled,
                created_at=created_at,
            ))

        return credentials

    # ---- Service Management ----

    async def list_services(self, tenant: str) -> list[str]:
        """List services for a tenant (OpCode 0x0401).

        Args:
            tenant: Tenant name

        Returns:
            List of service names
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)

        response = await self._client._send_request(
            OpCode(0x0401), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        count = reader.read_u16()
        services = []
        for _ in range(count):
            services.append(reader.read_string_u16())
        return services

    # ---- Config Management ----

    async def list_configs(self, tenant: str, group: str) -> list[AdminConfigItem]:
        """List configs for tenant/group (OpCode 0x0409).

        Args:
            tenant: Tenant name
            group: Group name

        Returns:
            List of AdminConfigItem
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_string_u16(group)

        response = await self._client._send_request(
            OpCode(0x0409), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        count = reader.read_u16()
        configs = []
        for _ in range(count):
            cfg_tenant = reader.read_string_u16()
            cfg_group = reader.read_string_u16()
            data_id = reader.read_string_u16()
            md5 = reader.read_bytes(16)
            length = reader.read_u32()
            deleted = reader.read_u8() == 1
            configs.append(AdminConfigItem(
                tenant=cfg_tenant,
                group=cfg_group,
                data_id=data_id,
                md5=md5,
                length=length,
                deleted=deleted,
            ))
        return configs

    async def publish_config(
        self, tenant: str, group: str, data_id: str, content: str
    ) -> bool:
        """Publish/create a config (OpCode 0x040B).

        Args:
            tenant: Tenant name
            group: Group name
            data_id: Config data ID
            content: Config content

        Returns:
            True if successful
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_string_u16(group)
        writer.write_string_u16(data_id)
        content_bytes = content.encode("utf-8")
        writer.write_u32(len(content_bytes))
        writer.write_bytes(content_bytes)

        response = await self._client._send_request(
            OpCode(0x040B), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        status = reader.read_u16()
        if status == StatusCode.OK:
            logger.info(f"Config published: {tenant}/{group}/{data_id}")
        return status == StatusCode.OK

    async def delete_config(self, tenant: str, group: str, data_id: str) -> bool:
        """Delete a config (OpCode 0x040D).

        Args:
            tenant: Tenant name
            group: Group name
            data_id: Config data ID

        Returns:
            True if successful
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)
        writer.write_string_u16(group)
        writer.write_string_u16(data_id)

        response = await self._client._send_request(
            OpCode(0x040D), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        status = reader.read_u16()
        if status == StatusCode.OK:
            logger.info(f"Config deleted: {tenant}/{group}/{data_id}")
        return status == StatusCode.OK

    # ---- Tenant Query ----

    async def list_tenants(self) -> list[AdminTenantItem]:
        """List all tenants (OpCode 0x0407).

        Returns:
            List of AdminTenantItem
        """
        response = await self._client._send_request(
            OpCode(0x0407), b""
        )

        reader = BinaryReader(response.body)
        count = reader.read_u16()
        tenants = []
        for _ in range(count):
            tenant = reader.read_string_u16()
            max_conns = reader.read_u32()
            rate_limit = reader.read_u32()
            policy_flags = reader.read_u16()
            tenants.append(AdminTenantItem(
                tenant=tenant,
                max_connections=max_conns,
                rate_limit_ops=rate_limit,
                policy_flags=policy_flags,
            ))
        return tenants

    async def get_tenant_policy(self, tenant: str) -> TenantPolicy | None:
        """Get tenant policy (OpCode 0x040D -> 0x040E).

        Args:
            tenant: Tenant name

        Returns:
            TenantPolicy or None if not found
        """
        writer = BinaryWriter()
        writer.write_string_u16(tenant)

        response = await self._client._send_request(
            OpCode(0x040D), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        found = reader.read_u8()
        if found == 0:
            return None

        policy_flags = reader.read_u16()
        max_conns = reader.read_u32()
        rate_limit = reader.read_u32()
        lease_duration = reader.read_u64()

        return TenantPolicy(
            tenant=tenant,
            policy_flags=policy_flags,
            max_connections=max_conns,
            rate_limit_ops=rate_limit,
            lease_duration_ms=lease_duration,
        )

    # ---- Governance State ----

    async def get_governance_state(self) -> GovernanceState:
        """Get governance state (OpCode 0x040F).

        Returns:
            GovernanceState with circuit breakers, coloring rules, outlier votes
        """
        response = await self._client._send_request(
            OpCode(0x040F), b""
        )

        reader = BinaryReader(response.body)

        # Parse circuit breakers
        cb_count = reader.read_u16()
        circuit_breakers = []
        for _ in range(cb_count):
            service_key = reader.read_string_u16()
            state = reader.read_u8()
            failure_count = reader.read_u32()
            circuit_breakers.append({
                "service_key": service_key,
                "state": state,
                "failure_count": failure_count,
            })

        # Parse coloring rules
        color_count = reader.read_u16()
        coloring_rules = []
        for _ in range(color_count):
            rule_key = reader.read_string_u16()
            rule_value = reader.read_string_u16()
            coloring_rules.append({
                "key": rule_key,
                "value": rule_value,
            })

        # Parse outlier votes
        vote_count = reader.read_u16()
        outlier_votes = []
        for _ in range(vote_count):
            suspect_id = reader.read_u64()
            vote_count_val = reader.read_u32()
            outlier_votes.append({
                "suspect_server_id": suspect_id,
                "vote_count": vote_count_val,
            })

        return GovernanceState(
            circuit_breakers=circuit_breakers,
            coloring_rules=coloring_rules,
            outlier_votes=outlier_votes,
        )

    # ---- Connection Migration ----

    async def migrate_connection(
        self,
        source_node_id: int,
        target_node_id: int,
        stream_id: int,
        graceful_wait_ms: int,
    ) -> bool:
        """Migrate connection between nodes (OpCode 0x0405).

        Args:
            source_node_id: Source node ID
            target_node_id: Target node ID
            stream_id: Stream ID to migrate
            graceful_wait_ms: Graceful wait time in ms

        Returns:
            True if successful
        """
        writer = BinaryWriter()
        writer.write_u64(source_node_id)
        writer.write_u64(target_node_id)
        writer.write_u32(stream_id)
        writer.write_u32(graceful_wait_ms)

        response = await self._client._send_request(
            OpCode(0x0405), writer.getvalue()
        )

        reader = BinaryReader(response.body)
        status = reader.read_u16()
        return status == StatusCode.OK
