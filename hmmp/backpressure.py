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

"""Backpressure controller for HMMP protocol.

Activated when server signals resource saturation (Flags bit2=1).
Implements proportional request delay using a token-bucket style approach.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class BackpressureController:
    """Local backpressure controller activated by server signals.

    When server sets FLAG_BACKPRESSURE (0x04) in response frames,
    this controller applies proportional request delays to reduce load.
    """

    # Base delay per request when backpressure is active (ms)
    BASE_DELAY_MS = 50

    # Max delay cap (ms)
    MAX_DELAY_MS = 2000

    # Recovery time after last backpressure signal (ms)
    RECOVERY_WINDOW_MS = 5000

    def __init__(self):
        self._active = False
        self._backpressure_start_time = 0.0
        self._delay_ms = self.BASE_DELAY_MS

    @property
    def is_active(self) -> bool:
        """Check if backpressure is currently active."""
        return self._active

    @property
    def current_delay_ms(self) -> float:
        """Get current delay in milliseconds (0 if not active)."""
        return self._delay_ms if self._active else 0

    def on_backpressure_signal(self) -> None:
        """Called when a response frame with FLAG_BACKPRESSURE is received."""
        if not self._active:
            self._active = True
            logger.warning("Backpressure activated, applying proportional request delays")

        self._backpressure_start_time = time.time() * 1000
        # Exponentially increase delay (up to cap)
        self._delay_ms = min(self._delay_ms * 2, self.MAX_DELAY_MS)

    def on_normal_response(self) -> None:
        """Called when a normal response (without backpressure flag) is received."""
        if self._active:
            elapsed = time.time() * 1000 - self._backpressure_start_time
            if elapsed > self.RECOVERY_WINDOW_MS:
                self._recover()
            else:
                # Gradually reduce delay
                self._delay_ms = max(self._delay_ms / 2, 10)

    def compute_delay_ms(self) -> float:
        """Compute the delay (ms) to apply before sending a new request.

        Non-blocking: callers should defer the send asynchronously rather than
        sleeping the calling thread.

        Returns:
            Delay in milliseconds, or 0 if no delay needed
        """
        if not self._active:
            return 0

        elapsed = time.time() * 1000 - self._backpressure_start_time
        if elapsed > self.RECOVERY_WINDOW_MS:
            # Recovery: no signal in recovery window
            self._recover()
            return 0

        return self._delay_ms

    async def apply_delay_if_needed(self) -> None:
        """Async version: apply delay if backpressure is active.

        Should be called before sending a new request.
        """
        delay = self.compute_delay_ms()
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)

    def _recover(self) -> None:
        """Recover from backpressure state."""
        if self._active:
            self._active = False
            self._delay_ms = self.BASE_DELAY_MS
            logger.info("Backpressure recovered, normal request rate resumed")

    def reset(self) -> None:
        """Reset the controller to initial state."""
        self._active = False
        self._delay_ms = self.BASE_DELAY_MS
        self._backpressure_start_time = 0

    def get_status(self) -> dict:
        """Get controller status as dict."""
        return {
            "active": self._active,
            "delay_ms": self._delay_ms if self._active else 0,
        }
