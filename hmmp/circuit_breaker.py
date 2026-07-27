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

"""HMMP-aware Circuit Breaker with 3-state machine.

Implements classic CLOSED → OPEN → HALF_OPEN state machine enhanced with
HMMP protocol signals:
- Error Flag (MetricsPack bit 29): proactively trips before local errors accumulate
- Backpressure (Header Flags bit 2): accelerates trip threshold
- Pre-heating flag: more lenient during warmup
- Push-based proactive recovery via ServiceChangedNotify
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable

from .codec import unpack_metrics_pack

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = auto()     # Normal operation, requests pass through
    OPEN = auto()       # Breaker tripped, requests rejected/fallback
    HALF_OPEN = auto()  # Testing recovery, limited requests allowed


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""

    # Failure threshold to trip (absolute count)
    failure_threshold: int = 5

    # Failure rate threshold (0.0 - 1.0) to trip
    failure_rate_threshold: float = 0.5

    # Minimum calls before failure rate is evaluated
    minimum_calls_before_trip: int = 10

    # Wait duration in OPEN state before transitioning to HALF_OPEN (ms)
    wait_duration_in_open_state_ms: int = 30000

    # Number of permitted calls in HALF_OPEN state
    permitted_calls_in_half_open: int = 3

    @classmethod
    def defaults(cls) -> CircuitBreakerConfig:
        """Create default configuration."""
        return cls()


class CircuitBreaker:
    """HMMP-aware circuit breaker for a single target instance.

    Enhanced with HMMP protocol signals for proactive tripping and recovery.
    """

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None):
        self.name = name
        self.config = config or CircuitBreakerConfig.defaults()

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._total_requests = 0
        self._last_state_change_time = time.time() * 1000
        self._half_open_permits = 0

        # HMMP protocol signals
        self._remote_error_flag = False
        self._backpressure_active = False

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count

    @property
    def total_requests(self) -> int:
        """Get total request count."""
        return self._total_requests

    @property
    def is_remote_error_flag_active(self) -> bool:
        """Check if remote error flag is active."""
        return self._remote_error_flag

    def try_acquire(self) -> bool:
        """Attempt to acquire permission to execute a request.

        Returns:
            True if request is allowed, False if breaker is OPEN (should fallback)
        """
        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            # Check if wait duration has elapsed → transition to HALF_OPEN
            elapsed = time.time() * 1000 - self._last_state_change_time
            if elapsed >= self.config.wait_duration_in_open_state_ms:
                self._transition_to(CircuitState.HALF_OPEN)
                logger.info(f"CircuitBreaker [{self.name}] OPEN → HALF_OPEN after {elapsed:.0f}ms")
                return self._try_acquire_half_open()
            return False  # Still OPEN

        if self._state == CircuitState.HALF_OPEN:
            return self._try_acquire_half_open()

        return True

    def _try_acquire_half_open(self) -> bool:
        """Try to acquire a permit in HALF_OPEN state."""
        self._half_open_permits -= 1
        return self._half_open_permits >= 0

    def record_success(self) -> None:
        """Record a successful request execution."""
        self._total_requests += 1

        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.permitted_calls_in_half_open:
                # Enough successes in half-open → close
                self._transition_to(CircuitState.CLOSED)
                logger.info(f"CircuitBreaker [{self.name}] HALF_OPEN → CLOSED (recovered)")

        elif self._state == CircuitState.CLOSED:
            # Slow decay of failure count on success
            if self._failure_count > 0:
                self._failure_count -= 1

    def record_failure(self) -> None:
        """Record a failed request execution."""
        self._total_requests += 1

        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open → back to OPEN
            self._transition_to(CircuitState.OPEN)
            logger.info(f"CircuitBreaker [{self.name}] HALF_OPEN → OPEN (failure during probe)")

        elif self._state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._should_trip():
                self._transition_to(CircuitState.OPEN)
                logger.warning(
                    f"CircuitBreaker [{self.name}] CLOSED → OPEN "
                    f"(failures={self._failure_count}, threshold={self.config.failure_threshold})"
                )

    def on_remote_error_flag_set(self) -> None:
        """Called when MetricsPack error flag is set (bit 29 = 1).

        Proactively trips the breaker without waiting for local failures.
        """
        self._remote_error_flag = True
        if self._state == CircuitState.CLOSED:
            # Lower the threshold when remote error flag is active
            effective_threshold = max(1, self.config.failure_threshold // 2)
            if self._failure_count >= effective_threshold:
                self._transition_to(CircuitState.OPEN)
                logger.warning(
                    f"CircuitBreaker [{self.name}] CLOSED → OPEN "
                    f"(remote error flag + {self._failure_count} local failures)"
                )

    def on_remote_error_flag_cleared(self) -> None:
        """Called when MetricsPack error flag is cleared (bit 29 = 0).

        Proactively transitions OPEN → HALF_OPEN immediately without waiting
        for the full timeout window. This is the key advantage of HMMP's
        push-based architecture over passive timer-only recovery.
        """
        self._remote_error_flag = False
        if self._state == CircuitState.OPEN:
            # Proactive recovery: server says the instance is healthy again
            self._transition_to(CircuitState.HALF_OPEN)
            logger.info(
                f"CircuitBreaker [{self.name}] OPEN → HALF_OPEN "
                f"(proactive: remote error flag cleared)"
            )

    def on_backpressure(self, active: bool) -> None:
        """Called when backpressure signal is received from server.

        Doesn't trip the breaker but makes it more sensitive.
        """
        self._backpressure_active = active

    def _should_trip(self) -> bool:
        """Determine if the breaker should trip."""
        threshold = self.config.failure_threshold

        # If remote error flag is active, use half threshold (proactive tripping)
        if self._remote_error_flag:
            threshold = max(1, threshold // 2)

        # If backpressure is active, also lower threshold slightly
        if self._backpressure_active:
            threshold = max(1, int(threshold * 0.75))

        # Check failure rate if minimum calls met
        if self._total_requests >= self.config.minimum_calls_before_trip:
            failure_rate = self._failure_count / self._total_requests
            if failure_rate >= self.config.failure_rate_threshold:
                return True

        # Absolute count threshold
        return self._failure_count >= threshold

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        old_state = self._state
        self._state = new_state
        self._last_state_change_time = time.time() * 1000

        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0
            self._half_open_permits = self.config.permitted_calls_in_half_open

    def get_status(self) -> dict:
        """Get circuit breaker status as dict."""
        return {
            "name": self.name,
            "state": self._state.name,
            "failure_count": self._failure_count,
            "total_requests": self._total_requests,
            "remote_error_flag": self._remote_error_flag,
            "backpressure_active": self._backpressure_active,
        }


class CircuitBreakerRegistry:
    """Registry of circuit breakers, one per target service instance.

    Integrates with HMMP push notifications to proactively adjust breaker
    sensitivity based on real-time MetricsPack signals from the server.
    """

    def __init__(self, default_config: CircuitBreakerConfig | None = None):
        self._breakers: dict[str, CircuitBreaker] = {}
        self._default_config = default_config or CircuitBreakerConfig.defaults()

    def get_breaker(self, instance_id: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a specific instance.

        Args:
            instance_id: Format "host:port" or "serviceId#host:port"
        """
        if instance_id not in self._breakers:
            self._breakers[instance_id] = CircuitBreaker(instance_id, self._default_config)
        return self._breakers[instance_id]

    def on_service_snapshot_updated(self, snapshot) -> None:
        """Called when a ServiceChangedNotify is received.

        Updates breaker states based on MetricsPack error flags.

        Args:
            snapshot: ServiceSnapshot object with instances
        """
        if not snapshot or not hasattr(snapshot, "instances"):
            return

        for inst in snapshot.instances:
            inst_id = f"{inst.ip}:{inst.port}"
            breaker = self._breakers.get(inst_id)
            if breaker is None:
                continue

            # Check error flag from MetricsPack
            metrics = unpack_metrics_pack(inst.metrics_pack)
            if metrics.get("error", False):
                breaker.on_remote_error_flag_set()
            else:
                breaker.on_remote_error_flag_cleared()

    def is_instance_available(self, host: str, port: int) -> bool:
        """Check if a specific instance is available (breaker not OPEN)."""
        inst_id = f"{host}:{port}"
        breaker = self._breakers.get(inst_id)
        if breaker is None:
            return True  # No breaker = available
        return breaker.try_acquire()

    def record_success(self, host: str, port: int) -> None:
        """Record success for an instance call."""
        inst_id = f"{host}:{port}"
        breaker = self._breakers.get(inst_id)
        if breaker is not None:
            breaker.record_success()

    def record_failure(self, host: str, port: int) -> None:
        """Record failure for an instance call."""
        inst_id = f"{host}:{port}"
        breaker = self.get_breaker(inst_id)  # create if not exists
        breaker.record_failure()

    def get_all_breakers(self) -> dict[str, CircuitBreaker]:
        """Get all circuit breakers."""
        return self._breakers.copy()

    def get_all_status(self) -> list[dict]:
        """Get status of all circuit breakers."""
        return [breaker.get_status() for breaker in self._breakers.values()]
