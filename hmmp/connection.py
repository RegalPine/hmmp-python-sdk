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

"""TCP connection management for HMMP protocol."""

from __future__ import annotations

import asyncio
import logging
import struct
from enum import Enum, auto
from typing import Any, Callable, Awaitable

from .constants import HEADER_SIZE, Flag, OpCode
from .frame import Frame, FrameDecoder, FrameHeader
from .exceptions import (
    ConnectionClosedError,
    ConnectionError,
    ProtocolError,
)

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection state machine states."""
    DISCONNECTED = auto()
    PENDING = auto()
    AUTHENTICATING = auto()
    AUTHENTICATED = auto()
    CLOSING = auto()


class HMMPConnection:
    """Low-level TCP connection for HMMP protocol.

    Handles:
    - TCP connection lifecycle
    - Frame reading/writing
    - Stream ID management (with overflow handling)
    - Connection state tracking

    Multiplexing:
    - Multiple concurrent requests over single TCP connection
    - Each request assigned unique Stream ID
    - Responses routed back by Stream ID
    - Stream ID 0 reserved for server push notifications
    """

    # Stream ID range: [1, 2^31-1], 0 reserved for push
    MAX_STREAM_ID = 0x7FFFFFFF

    def __init__(
        self,
        host: str,
        port: int,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._state = ConnectionState.DISCONNECTED
        self._stream_id_counter = 0
        self._lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._closed_event = asyncio.Event()
        self._frame_decoder = FrameDecoder()

        # Callbacks
        self._on_frame: Callable[[Frame], Awaitable[None]] | None = None
        self._on_close: Callable[[], Awaitable[None]] | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def is_connected(self) -> bool:
        return self._state in (
            ConnectionState.PENDING,
            ConnectionState.AUTHENTICATING,
            ConnectionState.AUTHENTICATED,
        )

    @property
    def is_authenticated(self) -> bool:
        return self._state == ConnectionState.AUTHENTICATED

    def next_stream_id(self) -> int:
        """Get next stream ID with overflow handling.

        Stream ID cycles within [1, MAX_STREAM_ID], skipping 0 (reserved for push).
        """
        self._stream_id_counter += 1
        if self._stream_id_counter > self.MAX_STREAM_ID:
            self._stream_id_counter = 1
        return self._stream_id_counter

    def set_frame_handler(self, handler: Callable[[Frame], Awaitable[None]]) -> None:
        """Set callback for incoming frames."""
        self._on_frame = handler

    def set_close_handler(self, handler: Callable[[], Awaitable[None]]) -> None:
        """Set callback for connection close."""
        self._on_close = handler

    async def connect(self) -> None:
        """Establish TCP connection."""
        if self._state != ConnectionState.DISCONNECTED:
            raise ConnectionError(f"Cannot connect in state {self._state}")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout,
            )
            self._state = ConnectionState.PENDING
            self._closed_event.clear()
            logger.info(f"Connected to {self.host}:{self.port}")
        except asyncio.TimeoutError:
            raise ConnectionError(f"Connection timeout to {self.host}:{self.port}")
        except OSError as e:
            raise ConnectionError(f"Connection failed to {self.host}:{self.port}: {e}")

    async def close(self) -> None:
        """Close the connection."""
        if self._state == ConnectionState.DISCONNECTED:
            return

        self._state = ConnectionState.CLOSING

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

        self._reader = None
        self._writer = None
        self._state = ConnectionState.DISCONNECTED
        self._closed_event.set()

        if self._on_close:
            await self._on_close()

        logger.info(f"Connection closed to {self.host}:{self.port}")

    async def wait_closed(self) -> None:
        """Wait for connection to close."""
        await self._closed_event.wait()

    async def send_frame(self, frame_data: bytes) -> None:
        """Send raw frame bytes."""
        if not self._writer:
            raise ConnectionClosedError("Not connected")

        async with self._lock:
            try:
                self._writer.write(frame_data)
                await self._writer.drain()
            except Exception as e:
                await self.close()
                raise ConnectionClosedError(f"Send failed: {e}")

    async def read_frame(self) -> Frame:
        """Read a complete frame from the connection.

        Returns:
            Decoded Frame object

        Raises:
            ConnectionClosedError: If connection is closed
            ProtocolError: If frame is malformed
        """
        if not self._reader:
            raise ConnectionClosedError("Not connected")

        async with self._read_lock:
            try:
                # Read header
                header_data = await asyncio.wait_for(
                    self._reader.readexactly(HEADER_SIZE),
                    timeout=self.read_timeout,
                )
                header = FrameHeader.from_bytes(header_data)

                # Calculate total frame size
                total_size = HEADER_SIZE + header.payload_length

                # Read remaining payload
                if header.payload_length > 0:
                    payload_data = await asyncio.wait_for(
                        self._reader.readexactly(header.payload_length),
                        timeout=self.read_timeout,
                    )
                    frame_data = header_data + payload_data
                else:
                    frame_data = header_data

                return self._frame_decoder.decode(frame_data)

            except asyncio.IncompleteReadError:
                await self.close()
                raise ConnectionClosedError("Connection closed during read")
            except asyncio.TimeoutError:
                raise ConnectionError("Read timeout")
            except ProtocolError:
                await self.close()
                raise

    async def read_frame_loop(self) -> None:
        """Continuously read frames and dispatch to handler.

        This should be run as a background task.
        """
        while self.is_connected:
            try:
                frame = await self.read_frame()

                if self._on_frame:
                    await self._on_frame(frame)

            except ConnectionClosedError:
                break
            except Exception as e:
                logger.error(f"Error in read loop: {e}")
                await self.close()
                break

    def set_state(self, state: ConnectionState) -> None:
        """Update connection state."""
        old_state = self._state
        self._state = state
        logger.debug(f"Connection state: {old_state} -> {state}")


class FrameRouter:
    """Routes incoming frames to appropriate handlers based on stream ID and OpCode.

    Multiplexing support:
    - Tracks pending requests by Stream ID
    - Routes responses to correct caller via Future
    - Handles server push notifications (Stream ID = 0)
    - Fails all pending requests on disconnect
    """

    def __init__(self):
        self._pending_requests: dict[int, asyncio.Future[Frame]] = {}
        self._notify_handlers: dict[int, Callable[[Frame], Awaitable[None]]] = {}
        self._global_handlers: list[Callable[[Frame], Awaitable[None]]] = []

    @property
    def pending_count(self) -> int:
        """Get number of pending requests."""
        return len(self._pending_requests)

    def register_request(self, stream_id: int) -> asyncio.Future[Frame]:
        """Register a pending request and return a future for the response."""
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending_requests[stream_id] = future
        return future

    def cancel_request(self, stream_id: int) -> None:
        """Cancel a pending request."""
        if stream_id in self._pending_requests:
            future = self._pending_requests.pop(stream_id)
            if not future.done():
                future.cancel()

    def fail_all(self, error: Exception) -> None:
        """Fail all pending requests (called on disconnect).

        Args:
            error: Exception to set on all pending futures
        """
        pending = list(self._pending_requests.items())
        self._pending_requests.clear()

        for stream_id, future in pending:
            if not future.done():
                future.set_exception(error)

        if pending:
            logger.warning(f"Failed {len(pending)} pending requests due to disconnect")

    def register_notify_handler(
        self, opcode: int, handler: Callable[[Frame], Awaitable[None]]
    ) -> None:
        """Register handler for server-initiated notifications (stream_id=0)."""
        self._notify_handlers[opcode] = handler

    def add_global_handler(self, handler: Callable[[Frame], Awaitable[None]]) -> None:
        """Add handler that receives all frames."""
        self._global_handlers.append(handler)

    async def route_frame(self, frame: Frame) -> None:
        """Route a frame to the appropriate handler."""
        # Call global handlers first
        for handler in self._global_handlers:
            try:
                await handler(frame)
            except Exception as e:
                logger.error(f"Global handler error: {e}")

        # Handle notifications (stream_id = 0)
        if frame.stream_id == 0:
            opcode = frame.body_type
            if opcode and opcode in self._notify_handlers:
                try:
                    await self._notify_handlers[opcode](frame)
                except Exception as e:
                    logger.error(f"Notify handler error for opcode {opcode}: {e}")
            return

        # Handle responses to pending requests
        if frame.stream_id in self._pending_requests:
            future = self._pending_requests.pop(frame.stream_id)
            if not future.done():
                future.set_result(frame)
