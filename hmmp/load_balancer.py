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

"""Adaptive load balancer for HMMP protocol.

Implements weighted load balancing based on MetricsPack multi-dimensional metrics.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .codec import unpack_metrics_pack

if TYPE_CHECKING:
    from .models import ServiceInstance, ServiceSnapshot

logger = logging.getLogger(__name__)


@dataclass
class WeightedInstance:
    """Instance with computed effective weight."""
    instance: ServiceInstance
    effective_weight: float
    declared_weight: float


class AdaptiveLoadBalancer:
    """Adaptive weighted load balancer based on HMMP MetricsPack.

    Scoring formula per instance:
        effectiveWeight = declaredWeight
                        × cpuFactor(cpu%)
                        × memoryFactor(mem%)
                        × connFactor(activeConns)
                        × latencyFactor(ewmaDelay)
                        × errorPenalty
                        × preheatPenalty

    Factors are designed so that healthier/less-loaded instances get higher scores.
    Instances with error flag or in pre-heating mode are heavily penalized but not
    excluded (allows graceful degradation rather than hard-cutoff).
    """

    def __init__(self):
        self._rng = random.Random()

    def select(self, snapshot: ServiceSnapshot) -> ServiceInstance | None:
        """Select an instance from snapshot using adaptive weighted random.

        Args:
            snapshot: ServiceSnapshot with instances

        Returns:
            Selected ServiceInstance, or None if no instances available
        """
        if not snapshot.instances:
            return None

        if len(snapshot.instances) == 1:
            return snapshot.instances[0]

        # Calculate adaptive effective weight for each instance
        weighted_instances = []
        total_weight = 0.0

        for inst in snapshot.instances:
            if not inst.healthy:
                continue  # Skip unhealthy instances

            ew = self._compute_effective_weight(inst)
            weighted_instances.append(WeightedInstance(
                instance=inst,
                effective_weight=ew,
                declared_weight=inst.weight,
            ))
            total_weight += ew

        if not weighted_instances:
            # All instances unhealthy, fallback to first
            return snapshot.instances[0]

        if total_weight <= 0:
            # Fallback: random selection
            return self._rng.choice(weighted_instances).instance

        # Weighted random selection
        random_value = self._rng.random() * total_weight
        cumulative = 0.0

        for wi in weighted_instances:
            cumulative += wi.effective_weight
            if random_value <= cumulative:
                return wi.instance

        return weighted_instances[-1].instance

    def select_with_circuit_breaker(
        self,
        snapshot: ServiceSnapshot,
        is_available: callable,
    ) -> ServiceInstance | None:
        """Select an instance, respecting circuit breaker state.

        Args:
            snapshot: ServiceSnapshot with instances
            is_available: Callable(host, port) -> bool to check circuit breaker

        Returns:
            Selected ServiceInstance, or None if no instances available
        """
        if not snapshot.instances:
            return None

        # Filter by circuit breaker availability
        available_instances = [
            inst for inst in snapshot.instances
            if inst.healthy and is_available(inst.ip, inst.port)
        ]

        if not available_instances:
            # All instances circuit-broken, try unhealthy but available
            available_instances = [
                inst for inst in snapshot.instances
                if is_available(inst.ip, inst.port)
            ]

        if not available_instances:
            # Complete failure, return None or first instance as last resort
            logger.warning("All instances circuit-broken, returning first as fallback")
            return snapshot.instances[0] if snapshot.instances else None

        # Create a temporary snapshot-like object for selection
        @dataclass
        class TempSnapshot:
            instances: list

        temp = TempSnapshot(instances=available_instances)
        return self.select(temp)

    def _compute_effective_weight(self, instance: ServiceInstance) -> float:
        """Compute the effective weight of an instance.

        Higher score = more likely to be selected.
        """
        # Base declared weight
        declared_weight = instance.weight if instance.weight > 0 else 1.0

        # Parse MetricsPack
        if instance.metrics_pack == 0:
            # No metrics available, use declared weight only
            return declared_weight

        metrics = unpack_metrics_pack(instance.metrics_pack)
        cpu = metrics.get("cpu_percent", 0)
        memory = metrics.get("memory_percent", 0)
        active_conns = metrics.get("active_conns", 0)
        ewma_delay = metrics.get("ewma_delay", 0)
        error_flag = metrics.get("error", False)
        preheating = metrics.get("preheating", False)

        # --- Factor calculations ---

        # CPU factor: linear decay from 1.0 (0% load) to 0.1 (100% load)
        # Aggressive penalty above 80%
        if cpu <= 60:
            cpu_factor = 1.0
        elif cpu <= 80:
            cpu_factor = 1.0 - (cpu - 60) * 0.015  # 60%→1.0, 80%→0.7
        else:
            cpu_factor = 0.7 - (cpu - 80) * 0.03  # 80%→0.7, 100%→0.1
        cpu_factor = max(0.05, cpu_factor)

        # Memory factor: gentle decay, aggressive only above 90%
        if memory <= 70:
            mem_factor = 1.0
        elif memory <= 90:
            mem_factor = 1.0 - (memory - 70) * 0.01  # 70%→1.0, 90%→0.8
        else:
            mem_factor = 0.8 - (memory - 90) * 0.06  # 90%→0.8, 100%→0.2
        mem_factor = max(0.05, mem_factor)

        # Connection factor: penalize high connection count
        if active_conns <= 200:
            conn_factor = 1.0
        elif active_conns <= 600:
            conn_factor = 1.0 - (active_conns - 200) * 0.001  # 200→1.0, 600→0.6
        else:
            conn_factor = 0.6 - (active_conns - 600) * 0.001  # 600→0.6, 1023→0.177
        conn_factor = max(0.05, conn_factor)

        # Latency factor: inverse relationship, higher delay = lower weight
        if ewma_delay <= 50:
            latency_factor = 1.0
        elif ewma_delay <= 200:
            latency_factor = 1.0 - (ewma_delay - 50) * 0.002  # 50→1.0, 200→0.7
        elif ewma_delay <= 1000:
            latency_factor = 0.7 - (ewma_delay - 200) * 0.0005  # 200→0.7, 1000→0.3
        else:
            latency_factor = 0.3 - (ewma_delay - 1000) * 0.0001  # 1000→0.3, 5000→0.1
        latency_factor = max(0.05, latency_factor)

        # Error penalty: circuit breaker or >50% error rate → severe penalty
        error_penalty = 0.1 if error_flag else 1.0

        # Pre-heating penalty: JIT warmup phase → moderate penalty (not excluded)
        preheat_penalty = 0.3 if preheating else 1.0

        # Final effective weight
        effective = (
            declared_weight
            * cpu_factor
            * mem_factor
            * conn_factor
            * latency_factor
            * error_penalty
            * preheat_penalty
        )

        return max(0.001, effective)  # Never exactly zero

    def compute_weights(self, snapshot: ServiceSnapshot) -> list[WeightedInstance]:
        """Compute effective weights for all instances (for debugging/monitoring).

        Args:
            snapshot: ServiceSnapshot with instances

        Returns:
            List of WeightedInstance with computed weights
        """
        result = []
        for inst in snapshot.instances:
            ew = self._compute_effective_weight(inst)
            result.append(WeightedInstance(
                instance=inst,
                effective_weight=ew,
                declared_weight=inst.weight,
            ))
        return result


class TrafficColorRouter:
    """Traffic coloring router based on governance TLV tags.

    Routes requests to instances matching the traffic color tag
    (e.g., "env=gray", "lane=canary-3").
    """

    def __init__(self, color_tag: str | None = None):
        self._color_tag = color_tag

    def set_color_tag(self, tag: str) -> None:
        """Set the traffic color tag to match."""
        self._color_tag = tag

    def clear_color_tag(self) -> None:
        """Clear the traffic color tag (disable color routing)."""
        self._color_tag = None

    def filter_instances(
        self,
        snapshot: ServiceSnapshot,
    ) -> list[ServiceInstance]:
        """Filter instances matching the traffic color tag.

        Args:
            snapshot: ServiceSnapshot with instances

        Returns:
            Filtered list of instances matching the color tag,
            or all instances if no tag is set or no matches found
        """
        if not self._color_tag:
            return snapshot.instances

        # Parse color tag (format: "key=value")
        if "=" not in self._color_tag:
            return snapshot.instances

        key, value = self._color_tag.split("=", 1)

        # Filter instances by metadata
        matched = []
        for inst in snapshot.instances:
            if inst.metadata.get(key) == value:
                matched.append(inst)

        if matched:
            logger.debug(
                f"Traffic color routing: {len(matched)}/{len(snapshot.instances)} "
                f"instances match '{self._color_tag}'"
            )
            return matched

        # No matches, return all (fallback)
        logger.debug(
            f"Traffic color routing: no instances match '{self._color_tag}', "
            f"falling back to all instances"
        )
        return snapshot.instances

    def route(
        self,
        snapshot: ServiceSnapshot,
        load_balancer: AdaptiveLoadBalancer | None = None,
    ) -> ServiceInstance | None:
        """Route to an instance matching traffic color, with load balancing.

        Args:
            snapshot: ServiceSnapshot with instances
            load_balancer: Optional load balancer for selection

        Returns:
            Selected ServiceInstance
        """
        filtered = self.filter_instances(snapshot)

        if not filtered:
            return None

        if load_balancer:
            # Create temporary snapshot with filtered instances
            @dataclass
            class TempSnapshot:
                instances: list
                service_name: str = ""
                topology_version: int = 0

            temp = TempSnapshot(instances=filtered)
            return load_balancer.select(temp)

        # Simple random selection
        return random.choice(filtered)
