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

"""Metrics collector for HMMP protocol.

Collects local runtime metrics and encodes them into a 32-bit MetricsPack
for embedding in HeartbeatPing frames (Section 9.5).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable

from .codec import pack_metrics_pack

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collects local runtime metrics for HMMP heartbeat reporting.

    Integration points:
    - CPU: psutil or /proc/stat (fallback: 0)
    - Memory: psutil or /proc/meminfo (fallback: 0)
    - Active connections: tracked via increment/decrement
    - EWMA delay: tracked by recording each request processing latency
    - Error flag: set externally by circuit breaker or error rate monitor
    - Pre-heating flag: automatically detected based on uptime or set externally
    """

    # Error rate threshold to auto-set error flag (50% per spec)
    ERROR_RATE_THRESHOLD = 0.5

    # EWMA smoothing factor (alpha)
    EWMA_ALPHA = 0.3

    # Pre-heating warmup duration in ms (default 2 minutes after start)
    DEFAULT_PREHEAT_DURATION_MS = 120_000

    def __init__(self, preheat_duration_ms: int | None = None):
        self._active_connections = 0
        self._ewma_delay_ms = 0.0
        self._total_requests = 0
        self._failed_requests = 0
        self._error_flag_override = False
        self._preheat_flag_override: bool | None = None
        self._preheat_duration_ms = preheat_duration_ms or self.DEFAULT_PREHEAT_DURATION_MS
        self._start_time_ms = time.time() * 1000

        # Optional custom metric providers
        self._cpu_provider: Callable[[], float] | None = None
        self._memory_provider: Callable[[], float] | None = None

    def set_cpu_provider(self, provider: Callable[[], float]) -> None:
        """Set custom CPU usage provider (returns percentage 0-100)."""
        self._cpu_provider = provider

    def set_memory_provider(self, provider: Callable[[], float]) -> None:
        """Set custom memory usage provider (returns percentage 0-100)."""
        self._memory_provider = provider

    def collect_metrics_pack(self) -> int:
        """Collect current metrics and encode into 32-bit MetricsPack.

        Called on each heartbeat interval.

        Returns:
            32-bit packed metrics value
        """
        cpu = self._get_cpu_usage()
        memory = self._get_memory_usage()
        conns = self._active_connections
        ewma_ms = int(self._ewma_delay_ms)
        err_flag = self._compute_error_flag()
        preheat = self._compute_preheat_flag()

        # Quantize values for MetricsPack
        cpu_quantized = min(31, int(cpu / 3.22))
        mem_quantized = min(31, int(memory / 3.22))
        conns_clipped = min(1023, conns)
        ewma_clipped = min(511, ewma_ms)

        pack = pack_metrics_pack(
            cpu=cpu_quantized,
            memory=mem_quantized,
            active_conns=conns_clipped,
            ewma_delay=ewma_clipped,
            error=err_flag,
            preheating=preheat,
            delay_scale=False,
        )

        logger.debug(
            f"MetricsPack collected: cpu={cpu:.1f}%, mem={memory:.1f}%, "
            f"conns={conns}, ewma={ewma_ms}ms, error={err_flag}, preheat={preheat}"
        )

        return pack

    # ---- Active connection tracking ----

    def increment_connections(self) -> None:
        """Increment active connection count.

        Call when an inbound request begins processing.
        """
        self._active_connections += 1

    def decrement_connections(self) -> None:
        """Decrement active connection count.

        Call when an inbound request completes.
        """
        self._active_connections = max(0, self._active_connections - 1)

    @property
    def active_connections(self) -> int:
        """Get current active connection count."""
        return self._active_connections

    # ---- Latency tracking (EWMA) ----

    def record_latency(self, latency_ms: float) -> None:
        """Record a request processing latency for EWMA calculation.

        Args:
            latency_ms: Processing time in milliseconds
        """
        if self._ewma_delay_ms == 0:
            self._ewma_delay_ms = latency_ms  # first sample
        else:
            self._ewma_delay_ms = (
                self.EWMA_ALPHA * latency_ms + (1.0 - self.EWMA_ALPHA) * self._ewma_delay_ms
            )

    @property
    def ewma_delay_ms(self) -> float:
        """Get current EWMA delay in milliseconds."""
        return self._ewma_delay_ms

    # ---- Error tracking ----

    def record_request(self, success: bool) -> None:
        """Record a request outcome for error rate calculation.

        Args:
            success: True if request succeeded, False if failed
        """
        self._total_requests += 1
        if not success:
            self._failed_requests += 1

    def set_error_flag(self, flag: bool) -> None:
        """Override error flag externally (e.g., by circuit breaker integration)."""
        self._error_flag_override = flag

    @property
    def error_rate(self) -> float:
        """Get current error rate (0.0 - 1.0)."""
        if self._total_requests == 0:
            return 0.0
        return self._failed_requests / self._total_requests

    def reset_error_counters(self) -> None:
        """Reset error counters (call periodically, e.g., every minute window)."""
        self._total_requests = 0
        self._failed_requests = 0

    # ---- Pre-heating control ----

    def set_preheat_flag(self, flag: bool | None) -> None:
        """Override preheat flag externally.

        Set to None to use auto-detection based on uptime.
        """
        self._preheat_flag_override = flag

    def set_preheat_duration_ms(self, ms: int) -> None:
        """Set the warmup duration for auto preheat detection."""
        self._preheat_duration_ms = ms

    # ---- Internal computations ----

    def _compute_error_flag(self) -> bool:
        """Compute error flag value."""
        if self._error_flag_override:
            return True
        # Auto-detect: error rate > 50%
        return self.error_rate >= self.ERROR_RATE_THRESHOLD

    def _compute_preheat_flag(self) -> bool:
        """Compute pre-heating flag value."""
        if self._preheat_flag_override is not None:
            return self._preheat_flag_override
        # Auto-detect: running less than preheat_duration_ms
        uptime_ms = time.time() * 1000 - self._start_time_ms
        return uptime_ms < self._preheat_duration_ms

    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage."""
        if self._cpu_provider:
            try:
                return self._cpu_provider()
            except Exception:
                pass

        # Try psutil
        try:
            import psutil
            return psutil.cpu_percent(interval=None)
        except ImportError:
            pass

        # Fallback: try /proc/stat on Linux
        try:
            return self._read_proc_cpu()
        except Exception:
            pass

        return 0.0

    def _get_memory_usage(self) -> float:
        """Get memory usage percentage."""
        if self._memory_provider:
            try:
                return self._memory_provider()
            except Exception:
                pass

        # Try psutil
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            pass

        # Fallback: try /proc/meminfo on Linux
        try:
            return self._read_proc_mem()
        except Exception:
            pass

        return 0.0

    def _read_proc_cpu(self) -> float:
        """Read CPU usage from /proc/stat (Linux only)."""
        with open("/proc/stat", "r") as f:
            line = f.readline()
        parts = line.split()
        if parts[0] != "cpu":
            return 0.0
        # user, nice, system, idle, iowait, irq, softirq, steal
        values = list(map(int, parts[1:9]))
        idle = values[3] + values[4]
        total = sum(values)
        if total == 0:
            return 0.0
        return (1.0 - idle / total) * 100.0

    def _read_proc_mem(self) -> float:
        """Read memory usage from /proc/meminfo (Linux only)."""
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if total == 0:
            return 0.0
        return (1.0 - available / total) * 100.0

    def get_status(self) -> dict:
        """Get collector status as dict."""
        return {
            "active_connections": self._active_connections,
            "ewma_delay_ms": self._ewma_delay_ms,
            "total_requests": self._total_requests,
            "failed_requests": self._failed_requests,
            "error_rate": self.error_rate,
            "error_flag": self._compute_error_flag(),
            "preheat_flag": self._compute_preheat_flag(),
        }
