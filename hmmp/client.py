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

Main client implementation for the High-Performance Microservice Multiplex Protocol.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from .codec import BinaryReader, BinaryWriter, compute_metadata_hash
from .connection import ConnectionState, FrameRouter, HMMPConnection
from .constants import (
    DEFAULT_NONCE_TTL_MS,
    HANDSHAKE_TIMEOUT_MS,
    META_BODY_TYPE,
    META_CANARY_LABELS,
    META_CONFIG_CIPHER_SUITE,
    META_CONFIG_CIPHER_SUITES,
    META_CONFIG_ENCRYPT,
    META_CONFIG_KEY_ID,
    META_CONFIG_KEY_ROTATION_MS,
    META_CANARY_ENABLED,
    META_CANARY_MATCH_RESULT,
    Flag,
    OpCode,
    StatusCode,
)
from .crypto import (
    compute_signature,
    compute_signature_v2,
    decrypt_config_body,
    derive_cek,
    derive_session_secret,
)
from .exceptions import (
    AuthenticationError,
    ConfigError,
    ConnectionClosedError,
    DecryptionError,
    HandshakeError,
    HandshakeTimeoutError,
    HMMPError,
    NonceError,
    RedirectError,
    ServiceError,
    ShutdownNoticeError,
    TimeoutError,
)
from .frame import Frame, FrameEncoder
from .governance import GovernanceBlock, parse_governance_block
from .models import (
    ConfigChangedNotification,
    ConfigEntry,
    FilterExpression,
    FilteredServiceSnapshot,
    HandshakeResult,
    ListenConfigEntry,
    NonceChallengeResult,
    RedirectInfo,
    ServiceInstance,
    ServiceSnapshot,
    ShutdownNotice,
)

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """HMMP client configuration."""

    host: str = "127.0.0.1"
    port: int = 8847
    client_id: str = ""
    access_key: str = ""
    secret_key: str = ""
    namespace: str = "public"

    # Connection settings
    connect_timeout: float = 5.0
    request_timeout: float = 10.0
    heartbeat_interval: float = 5.0
    reconnect_interval: float = 1.0
    max_reconnect_interval: float = 60.0
    auto_reconnect: bool = True

    # Security settings
    use_nonce_challenge: bool = True
    config_encrypt: bool = False
    config_cipher_suites: list[str] = field(default_factory=lambda: ["AES-256-GCM"])

    # Canary settings
    canary_labels: dict[str, str] = field(default_factory=dict)

    # Labels for handshake
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.client_id:
            self.client_id = f"hmmp-client-{uuid.uuid4().hex[:12]}"


class HMMPClient:
    """HMMP Protocol Client.

    Provides:
    - Connection lifecycle management (handshake, heartbeat, reconnection)
    - Service registration and discovery
    - Configuration management with encryption support
    - Server push notification handling
    """

    def __init__(self, config: ClientConfig):
        self.config = config
        self._conn: HMMPConnection | None = None
        self._encoder = FrameEncoder()
        self._router = FrameRouter()

        # Session state
        self._session_id: str = ""
        self._server_nonce: bytes = b""
        self._nonce_ttl_ms: int = DEFAULT_NONCE_TTL_MS

        # Encryption state
        self._cek: bytes = b""
        self._config_key_id: str = ""
        self._config_key_rotation_ms: int = 0
        self._cipher_suite: str = ""
        self._decryption_failures: int = 0

        # Background tasks
        self._read_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._running = False

        # Notification handlers
        self._service_change_handlers: dict[str, list[Callable[[ServiceSnapshot], Awaitable[None]]]] = {}
        self._config_change_handlers: dict[str, list[Callable[[ConfigChangedNotification], Awaitable[None]]]] = {}
        self._shutdown_handlers: list[Callable[[ShutdownNotice], Awaitable[None]]] = []
        self._redirect_handlers: list[Callable[[RedirectInfo], Awaitable[None]]] = []

        # Config chunk assembly
        self._config_chunks: dict[str, dict[int, bytes]] = {}

    @property
    def is_connected(self) -> bool:
        """Check if client is connected and authenticated."""
        return self._conn is not None and self._conn.is_authenticated

    @property
    def session_id(self) -> str:
        """Get current session ID."""
        return self._session_id

    async def connect(self) -> None:
        """Connect to HMMP server and perform handshake."""
        if self._running:
            return

        self._running = True
        await self._establish_connection()

    async def _establish_connection(self) -> None:
        """Establish connection and perform handshake."""
        self._conn = HMMPConnection(
            host=self.config.host,
            port=self.config.port,
            connect_timeout=self.config.connect_timeout,
            read_timeout=self.config.request_timeout,
        )
        self._conn.set_frame_handler(self._router.route_frame)
        self._conn.set_close_handler(self._on_connection_close)

        await self._conn.connect()

        # Setup notification handlers
        self._router.register_notify_handler(
            OpCode.SERVICE_CHANGED_NOTIFY, self._handle_service_changed
        )
        self._router.register_notify_handler(
            OpCode.CONFIG_CHANGED_NOTIFY, self._handle_config_changed
        )
        self._router.register_notify_handler(
            OpCode.INSTANCE_SHUTDOWN_PREPARE_NOTICE, self._handle_shutdown_notice
        )
        self._router.register_notify_handler(
            OpCode.CLUSTER_NODE_REDIRECT_NOTIFY, self._handle_redirect
        )

        # Perform handshake
        await self._handshake()

        # Start background tasks
        self._read_task = asyncio.create_task(self._conn.read_frame_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info(f"Connected and authenticated. Session: {self._session_id}")

    async def _handshake(self) -> None:
        """Perform handshake with optional nonce challenge."""
        self._conn.set_state(ConnectionState.AUTHENTICATING)

        # Step 1: Nonce challenge (if enabled)
        if self.config.use_nonce_challenge:
            await self._nonce_challenge()

        # Step 2: Handshake request
        await self._send_handshake_request()

    async def _nonce_challenge(self) -> None:
        """Perform nonce challenge for anti-replay protection."""
        timestamp = int(time.time() * 1000)

        # Build NonceChallengeRequest body
        writer = BinaryWriter()
        writer.write_string_u8(self.config.client_id)
        writer.write_u64(timestamp)

        stream_id = self._conn.next_stream_id()
        frame_data = self._encoder.encode(
            OpCode.NONCE_CHALLENGE_REQUEST,
            body=writer.getvalue(),
            stream_id=stream_id,
            is_request=True,
        )

        # Send and wait for response
        future = self._router.register_request(stream_id)
        await self._conn.send_frame(frame_data)

        try:
            response = await asyncio.wait_for(future, timeout=self.config.request_timeout)
        except asyncio.TimeoutError:
            self._router.cancel_request(stream_id)
            raise NonceError("Nonce challenge timeout")

        # Parse NonceChallengeResponse
        result = NonceChallengeResult.from_bytes(response.body)

        if result.status != 0:
            raise NonceError(f"Nonce challenge failed with status {result.status}", result.status)

        self._server_nonce = result.server_nonce
        self._nonce_ttl_ms = result.nonce_ttl_ms

        logger.debug(f"Nonce challenge successful, TTL: {result.nonce_ttl_ms}ms")

    async def _send_handshake_request(self) -> None:
        """Send HandshakeRequest and process response."""
        timestamp = int(time.time() * 1000)

        # Compute signature
        if self._server_nonce:
            signature = compute_signature_v2(
                self.config.secret_key,
                self.config.client_id,
                timestamp,
                self._server_nonce,
            )
        else:
            signature = compute_signature(
                self.config.secret_key,
                self.config.client_id,
                timestamp,
            )

        # Build HandshakeRequest body
        writer = BinaryWriter()
        writer.write_string_u8(self.config.client_id)
        writer.write_string_u8(self.config.access_key)
        writer.write_u64(timestamp)
        writer.write_string_u8(signature)

        # Nonce field
        if self._server_nonce:
            writer.write_u8(1)  # nonce_present
            writer.write_bytes(self._server_nonce)
        else:
            writer.write_u8(0)  # nonce_present

        # Labels
        labels = list(self.config.labels.items())
        writer.write_u8(len(labels))
        for key, value in labels:
            writer.write_string_u8(key)
            writer.write_string_u8(value)

        # Build metadata
        metadata: dict[str, Any] = {}
        if self.config.config_encrypt:
            metadata[META_CONFIG_ENCRYPT] = True
            metadata[META_CONFIG_CIPHER_SUITES] = self.config.config_cipher_suites
        if self.config.canary_labels:
            metadata[META_CANARY_LABELS] = self.config.canary_labels

        stream_id = self._conn.next_stream_id()
        frame_data = self._encoder.encode(
            OpCode.HANDSHAKE_REQUEST,
            body=writer.getvalue(),
            stream_id=stream_id,
            is_request=True,
            metadata=metadata,
        )

        # Send and wait for response
        future = self._router.register_request(stream_id)
        await self._conn.send_frame(frame_data)

        try:
            response = await asyncio.wait_for(future, timeout=self.config.request_timeout)
        except asyncio.TimeoutError:
            self._router.cancel_request(stream_id)
            raise HandshakeTimeoutError("Handshake timeout")

        # Parse HandshakeResponse
        result = self._parse_handshake_response(response)

        if result.status != StatusCode.OK:
            raise HandshakeError(f"Handshake failed with status {result.status}", result.status)

        self._session_id = result.session_id
        self._cipher_suite = result.config_cipher_suite
        self._config_key_id = result.config_key_id
        self._config_key_rotation_ms = result.config_key_rotation_ms

        # Derive CEK if encryption is enabled
        if self._cipher_suite and self._config_key_id:
            timestamp_ms = int(time.time() * 1000)
            session_secret = derive_session_secret(
                self.config.client_id, timestamp_ms, self.config.secret_key
            )
            self._cek = derive_cek(session_secret, self._config_key_id)

        self._conn.set_state(ConnectionState.AUTHENTICATED)

    def _parse_handshake_response(self, frame: Frame) -> HandshakeResult:
        """Parse HandshakeResponse frame."""
        reader = BinaryReader(frame.body)

        # Parse session_id and status from body
        session_id = reader.read_string_u16()
        status = reader.read_u16()

        result = HandshakeResult(session_id=session_id, status=status)

        # Extract encryption info from metadata
        result.config_cipher_suite = frame.metadata.get(META_CONFIG_CIPHER_SUITE, "")
        result.config_key_id = frame.metadata.get(META_CONFIG_KEY_ID, "")
        result.config_key_rotation_ms = frame.metadata.get(META_CONFIG_KEY_ROTATION_MS, 0)
        result.canary_enabled = frame.metadata.get(META_CANARY_ENABLED, False)
        result.canary_match_result = frame.metadata.get(META_CANARY_MATCH_RESULT, {})

        return result

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat pings."""
        while self._running and self._conn and self._conn.is_connected:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)

                if not self._conn.is_connected:
                    break

                stream_id = self._conn.next_stream_id()
                frame_data = self._encoder.encode(
                    OpCode.HEARTBEAT_PING,
                    body=b"",
                    stream_id=stream_id,
                    is_request=True,
                )

                future = self._router.register_request(stream_id)
                await self._conn.send_frame(frame_data)

                try:
                    await asyncio.wait_for(future, timeout=self.config.request_timeout)
                except asyncio.TimeoutError:
                    self._router.cancel_request(stream_id)
                    logger.warning("Heartbeat timeout")

            except ConnectionClosedError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

    async def _on_connection_close(self) -> None:
        """Handle connection close."""
        logger.warning("Connection closed")

        if self._running and self.config.auto_reconnect:
            await self._reconnect()

    async def _reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        interval = self.config.reconnect_interval

        while self._running:
            try:
                logger.info(f"Reconnecting in {interval}s...")
                await asyncio.sleep(interval)

                await self._establish_connection()
                logger.info("Reconnected successfully")
                return

            except Exception as e:
                logger.error(f"Reconnect failed: {e}")
                interval = min(interval * 2, self.config.max_reconnect_interval)

    async def disconnect(self) -> None:
        """Disconnect from server."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._read_task:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass

        if self._conn:
            await self._conn.close()

        logger.info("Disconnected")

    async def _send_request(
        self,
        opcode: OpCode,
        body: bytes = b"",
        metadata: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Frame:
        """Send a request and wait for response."""
        if not self._conn or not self._conn.is_authenticated:
            raise ConnectionClosedError("Not connected")

        stream_id = self._conn.next_stream_id()
        frame_data = self._encoder.encode(
            opcode,
            body=body,
            stream_id=stream_id,
            is_request=True,
            metadata=metadata,
        )

        future = self._router.register_request(stream_id)
        await self._conn.send_frame(frame_data)

        try:
            return await asyncio.wait_for(
                future, timeout=timeout or self.config.request_timeout
            )
        except asyncio.TimeoutError:
            self._router.cancel_request(stream_id)
            raise TimeoutError(f"Request timeout for opcode {opcode}")

    # ==================== Service Discovery ====================

    async def register_instance(self, instance: ServiceInstance) -> None:
        """Register a service instance."""
        body = instance.to_register_bytes()
        await self._send_request(OpCode.REGISTER_INSTANCE_REQUEST, body)
        logger.info(f"Registered instance: {instance.service_name} @ {instance.ip}:{instance.port}")

    async def register_instance_with_metadata(self, instance: ServiceInstance) -> tuple[int, int]:
        """Register a service instance with metadata.

        Returns:
            Tuple of (topology_version, metadata_hash)
        """
        body = instance.to_register_with_meta_bytes()
        response = await self._send_request(OpCode.REGISTER_INSTANCE_WITH_META_REQUEST, body)

        reader = BinaryReader(response.body)
        topology_version = reader.read_u64()
        metadata_hash = reader.read_u64()

        logger.info(f"Registered instance with metadata: {instance.service_name}")
        return topology_version, metadata_hash

    async def deregister_instance(self, instance: ServiceInstance) -> None:
        """Deregister a service instance."""
        body = instance.to_deregister_bytes()
        await self._send_request(OpCode.DEREGISTER_INSTANCE_REQUEST, body)
        logger.info(f"Deregistered instance: {instance.service_name} @ {instance.ip}:{instance.port}")

    async def discover_service(self, service_name: str) -> ServiceSnapshot:
        """Discover service instances."""
        writer = BinaryWriter()
        writer.write_string_u16(service_name)

        response = await self._send_request(
            OpCode.DISCOVER_SERVICE_REQUEST, writer.getvalue()
        )

        return ServiceSnapshot.from_bytes(response.body)

    async def discover_service_by_filter(
        self,
        service_name: str,
        filter_expr: FilterExpression | None = None,
        include_metadata: bool = False,
        tenant: str | None = None,
    ) -> FilteredServiceSnapshot:
        """Discover service instances with filter."""
        writer = BinaryWriter()
        writer.write_string_u16(tenant or self.config.namespace)
        writer.write_string_u16(service_name)

        if filter_expr:
            filter_bytes = filter_expr.to_bytes()
            writer.write_u16(len(filter_bytes))
            writer.write_bytes(filter_bytes)
        else:
            writer.write_u16(0)

        writer.write_u8(1 if include_metadata else 0)

        response = await self._send_request(
            OpCode.DISCOVER_SERVICE_BY_FILTER_REQUEST, writer.getvalue()
        )

        return FilteredServiceSnapshot.from_bytes(response.body, include_metadata)

    def on_service_change(
        self, service_name: str, handler: Callable[[ServiceSnapshot], Awaitable[None]]
    ) -> None:
        """Register handler for service change notifications."""
        if service_name not in self._service_change_handlers:
            self._service_change_handlers[service_name] = []
        self._service_change_handlers[service_name].append(handler)

    async def _handle_service_changed(self, frame: Frame) -> None:
        """Handle ServiceChangedNotify."""
        snapshot = ServiceSnapshot.from_bytes(frame.body)

        handlers = self._service_change_handlers.get(snapshot.service_name, [])
        for handler in handlers:
            try:
                await handler(snapshot)
            except Exception as e:
                logger.error(f"Service change handler error: {e}")

    # ==================== Configuration Management ====================

    async def get_config(
        self,
        data_id: str,
        group: str = "DEFAULT_GROUP",
        tenant: str | None = None,
    ) -> ConfigEntry:
        """Get configuration content."""
        entry = ConfigEntry(
            tenant=tenant or self.config.namespace,
            group=group,
            data_id=data_id,
        )

        body = entry.to_get_request_bytes(
            self.config.canary_labels if self.config.canary_labels else None
        )

        response = await self._send_request(OpCode.GET_CONFIG_REQUEST, body)

        # Handle encrypted response
        if response.header.is_encrypted and self._cek:
            try:
                decrypted_body = decrypt_config_body(
                    response.body,
                    self._cek,
                    response.stream_id,
                    OpCode.CONFIG_RESPONSE,
                )
                response.body = decrypted_body
                self._decryption_failures = 0
            except DecryptionError as e:
                self._decryption_failures += 1
                logger.error(f"Config decryption failed ({self._decryption_failures}): {e}")
                if self._decryption_failures >= 3:
                    logger.warning("Too many decryption failures, re-negotiation needed")
                raise

        result = ConfigEntry.from_response_bytes(response.body)

        # Handle chunked response
        if result.total_chunks > 1:
            result = await self._assemble_config_chunks(result, response.stream_id)

        return result

    async def _assemble_config_chunks(
        self, first_chunk: ConfigEntry, stream_id: int
    ) -> ConfigEntry:
        """Assemble multi-chunk config response."""
        key = f"{first_chunk.tenant}/{first_chunk.group}/{first_chunk.data_id}"
        self._config_chunks[key] = {first_chunk.chunk_index: first_chunk.content}

        # Wait for remaining chunks (they come as separate frames)
        # In practice, chunks arrive sequentially, so we just collect them
        while len(self._config_chunks[key]) < first_chunk.total_chunks:
            await asyncio.sleep(0.01)  # Small delay to allow chunk processing

        # Assemble
        chunks = self._config_chunks.pop(key)
        full_content = b"".join(chunks[i] for i in range(first_chunk.total_chunks))
        first_chunk.content = full_content
        first_chunk.total_chunks = 1
        first_chunk.chunk_index = 0

        return first_chunk

    async def listen_config(
        self,
        configs: list[ListenConfigEntry],
    ) -> None:
        """Subscribe to configuration changes."""
        writer = BinaryWriter()
        writer.write_u16(len(configs))
        for config in configs:
            writer.write_bytes(config.to_bytes())

        await self._send_request(OpCode.LISTEN_CONFIG_REQUEST, writer.getvalue())
        logger.info(f"Listening to {len(configs)} config(s)")

    def on_config_change(
        self,
        data_id: str,
        handler: Callable[[ConfigChangedNotification], Awaitable[None]],
        group: str = "DEFAULT_GROUP",
        tenant: str | None = None,
    ) -> None:
        """Register handler for config change notifications."""
        key = f"{tenant or self.config.namespace}/{group}/{data_id}"
        if key not in self._config_change_handlers:
            self._config_change_handlers[key] = []
        self._config_change_handlers[key].append(handler)

    async def _handle_config_changed(self, frame: Frame) -> None:
        """Handle ConfigChangedNotify."""
        # Handle encrypted notification
        body = frame.body
        if frame.header.is_encrypted and self._cek:
            try:
                body = decrypt_config_body(
                    frame.body,
                    self._cek,
                    frame.stream_id,
                    OpCode.CONFIG_CHANGED_NOTIFY,
                )
            except DecryptionError as e:
                logger.error(f"Config notify decryption failed: {e}")
                return

        notification = ConfigChangedNotification.from_bytes(body)
        key = f"{notification.tenant}/{notification.group}/{notification.data_id}"

        handlers = self._config_change_handlers.get(key, [])
        for handler in handlers:
            try:
                await handler(notification)
            except Exception as e:
                logger.error(f"Config change handler error: {e}")

    # ==================== Server Notifications ====================

    def on_shutdown(self, handler: Callable[[ShutdownNotice], Awaitable[None]]) -> None:
        """Register handler for server shutdown notice."""
        self._shutdown_handlers.append(handler)

    async def _handle_shutdown_notice(self, frame: Frame) -> None:
        """Handle InstanceShutdownPrepareNotice."""
        notice = ShutdownNotice.from_bytes(frame.body)
        logger.warning(f"Server shutdown in {notice.shutdown_delay_ms}ms")

        for handler in self._shutdown_handlers:
            try:
                await handler(notice)
            except Exception as e:
                logger.error(f"Shutdown handler error: {e}")

    def on_redirect(self, handler: Callable[[RedirectInfo], Awaitable[None]]) -> None:
        """Register handler for connection redirect."""
        self._redirect_handlers.append(handler)

    async def _handle_redirect(self, frame: Frame) -> None:
        """Handle ClusterNodeRedirectNotify."""
        redirect = RedirectInfo.from_bytes(frame.body)
        logger.info(
            f"Redirect to {redirect.target_ip}:{redirect.target_port} "
            f"(reason={redirect.reason}, wait={redirect.graceful_wait_ms}ms)"
        )

        for handler in self._redirect_handlers:
            try:
                await handler(redirect)
            except Exception as e:
                logger.error(f"Redirect handler error: {e}")

        # Auto-migrate connection
        await self._migrate_connection(redirect)

    async def _migrate_connection(self, redirect: RedirectInfo) -> None:
        """Migrate connection to new server."""
        # Wait for graceful period
        await asyncio.sleep(redirect.graceful_wait_ms / 1000.0)

        # Update config and reconnect
        self.config.host = redirect.target_ip
        self.config.port = redirect.target_port

        if self._conn:
            await self._conn.close()

        if self._running:
            await self._establish_connection()

    # ==================== Context Manager ====================

    async def __aenter__(self) -> HMMPClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()
