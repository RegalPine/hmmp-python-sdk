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

"""Local caching for HMMP protocol.

Provides:
- Service snapshot cache with TTL and topology_version guard
- Config cache with MD5 tracking and TTL
- Config snapshot file persistence for fault tolerance
- Canary version vector tracking
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class CanaryVersion:
    """Canary version tracking info (Section 7.3.8)."""

    version_id: str
    stable_version_id: str
    md5: bytes
    received_at: float = field(default_factory=time.time)

    @property
    def is_canary(self) -> bool:
        """Check if this is a canary version (not stable)."""
        return self.version_id != self.stable_version_id


class ServiceSnapshotCache:
    """Local cache for service discovery snapshots.

    Features:
    - TTL-based expiration (fallback for missed pushes)
    - topology_version monotonic guard (ignore stale updates)
    - metadata_hash change detection
    """

    def __init__(self, ttl_ms: int = 30000):
        self._cache: dict[str, Any] = {}  # cacheKey -> ServiceSnapshot
        self._fetch_time: dict[str, float] = {}  # cacheKey -> timestamp
        self._metadata_hash_cache: dict[str, int] = {}  # "ip:port" -> hash
        self._ttl_ms = ttl_ms

    def cache_key(self, tenant: str, group: str, service_name: str) -> str:
        """Generate cache key."""
        return f"{tenant}+{group}+{service_name}"

    def get(self, tenant: str, group: str, service_name: str) -> Any | None:
        """Get cached snapshot if valid (not expired)."""
        key = self.cache_key(tenant, group, service_name)
        cached = self._cache.get(key)
        fetched_at = self._fetch_time.get(key)

        if cached is not None and fetched_at is not None:
            elapsed = time.time() * 1000 - fetched_at
            if elapsed < self._ttl_ms:
                return cached

        return None

    def put(self, tenant: str, group: str, service_name: str, snapshot: Any) -> bool:
        """Put snapshot into cache with topology_version guard.

        Returns:
            True if snapshot was accepted, False if rejected (stale version)
        """
        key = self.cache_key(tenant, group, service_name)

        # topology_version monotonic guard
        existing = self._cache.get(key)
        if existing is not None and hasattr(existing, "topology_version"):
            if hasattr(snapshot, "topology_version"):
                if snapshot.topology_version <= existing.topology_version:
                    logger.debug(
                        f"Ignoring stale snapshot for {service_name} "
                        f"(ver {snapshot.topology_version} <= {existing.topology_version})"
                    )
                    return False

        self._cache[key] = snapshot
        self._fetch_time[key] = time.time() * 1000

        # Detect metadata_hash changes
        self._detect_metadata_hash_changes(snapshot)

        return True

    def invalidate(self, tenant: str, group: str, service_name: str) -> None:
        """Invalidate a cached snapshot."""
        key = self.cache_key(tenant, group, service_name)
        self._cache.pop(key, None)
        self._fetch_time.pop(key, None)

    def _detect_metadata_hash_changes(self, snapshot: Any) -> None:
        """Detect metadata_hash changes per instance."""
        if not hasattr(snapshot, "instances") or not snapshot.instances:
            return

        for inst in snapshot.instances:
            inst_key = f"{inst.ip}:{inst.port}"
            previous_hash = self._metadata_hash_cache.get(inst_key)
            current_hash = getattr(inst, "metadata_hash", 0)

            self._metadata_hash_cache[inst_key] = current_hash

            if previous_hash is not None and previous_hash != current_hash:
                logger.info(
                    f"Instance {inst_key} metadata_hash changed: "
                    f"{previous_hash:#x} -> {current_hash:#x}"
                )


class ConfigCache:
    """Local cache for configuration content.

    Features:
    - TTL-based expiration
    - MD5 tracking for change detection
    - File snapshot persistence for fault tolerance
    """

    def __init__(self, ttl_ms: int = 30000, snapshot_dir: str | None = None):
        self._cache: dict[str, str] = {}  # configKey -> content
        self._fetch_time: dict[str, float] = {}  # configKey -> timestamp
        self._md5_cache: dict[str, bytes] = {}  # configKey -> MD5
        self._ttl_ms = ttl_ms
        self._snapshot_dir: Path | None = None

        if snapshot_dir:
            self.enable_snapshot_dir(snapshot_dir)

    def enable_snapshot_dir(self, dir_path: str) -> None:
        """Enable local snapshot persistence for fault tolerance."""
        path = Path(dir_path)
        try:
            path.mkdir(parents=True, exist_ok=True)
            self._snapshot_dir = path
            logger.info(f"Config snapshot directory enabled: {path.absolute()}")
        except OSError as e:
            logger.warning(f"Failed to create snapshot dir: {dir_path}: {e}")

    def config_key(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> str:
        """Generate config cache key."""
        key = f"{tenant}+{group}+{data_id}"
        if tag:
            key += f"+tag:{tag}"
        return key

    def get(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> str | None:
        """Get cached config if valid (not expired)."""
        key = self.config_key(tenant, group, data_id, tag)
        cached = self._cache.get(key)
        fetched_at = self._fetch_time.get(key)

        if cached is not None and fetched_at is not None:
            elapsed = time.time() * 1000 - fetched_at
            if elapsed < self._ttl_ms:
                return cached

        return None

    def put(
        self,
        tenant: str,
        group: str,
        data_id: str,
        content: str,
        tag: str | None = None,
    ) -> None:
        """Put config content into cache."""
        key = self.config_key(tenant, group, data_id, tag)
        self._cache[key] = content
        self._fetch_time[key] = time.time() * 1000
        self._md5_cache[key] = self._compute_md5(content)
        self._save_snapshot(key, content)

    def remove(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> None:
        """Remove config from cache."""
        key = self.config_key(tenant, group, data_id, tag)
        self._cache.pop(key, None)
        self._fetch_time.pop(key, None)
        self._md5_cache.pop(key, None)
        self._delete_snapshot(key)

    def invalidate(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> None:
        """Invalidate cached config (same as remove but keeps snapshot)."""
        key = self.config_key(tenant, group, data_id, tag)
        self._cache.pop(key, None)
        self._fetch_time.pop(key, None)
        self._md5_cache.pop(key, None)

    def get_md5(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> bytes | None:
        """Get cached MD5 for config."""
        key = self.config_key(tenant, group, data_id, tag)
        return self._md5_cache.get(key)

    def load_from_snapshot(self, tenant: str, group: str, data_id: str, tag: str | None = None) -> str | None:
        """Load config from snapshot file (fault tolerance fallback)."""
        key = self.config_key(tenant, group, data_id, tag)
        if self._snapshot_dir is None:
            return None

        file_path = self._snapshot_dir / self._sanitize_filename(key)
        if not file_path.exists():
            return None

        try:
            content = file_path.read_text(encoding="utf-8")
            logger.info(f"Loaded config from snapshot: {key}")
            # Restore to cache
            self._cache[key] = content
            self._fetch_time[key] = time.time() * 1000
            self._md5_cache[key] = self._compute_md5(content)
            return content
        except OSError as e:
            logger.warning(f"Failed to read config snapshot: {key}: {e}")
            return None

    def _save_snapshot(self, key: str, content: str) -> None:
        """Save config to snapshot file."""
        if self._snapshot_dir is None:
            return
        try:
            file_path = self._snapshot_dir / self._sanitize_filename(key)
            file_path.write_text(content, encoding="utf-8")
        except OSError as e:
            logger.warning(f"Failed to save config snapshot: {key}: {e}")

    def _delete_snapshot(self, key: str) -> None:
        """Delete config snapshot file."""
        if self._snapshot_dir is None:
            return
        try:
            file_path = self._snapshot_dir / self._sanitize_filename(key)
            file_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _sanitize_filename(self, key: str) -> str:
        """Sanitize cache key for use as filename."""
        return key.replace("+", "_").replace("/", "_").replace("\\", "_")

    @staticmethod
    def _compute_md5(content: str) -> bytes:
        """Compute MD5 hash of content."""
        return hashlib.md5(content.encode("utf-8")).digest()


class CanaryVersionVector:
    """Canary version vector tracking (Section 7.3.8).

    Maintains a map of config keys to their canary version info.
    """

    def __init__(self):
        self._versions: dict[str, CanaryVersion] = {}

    def config_key(self, tenant: str, group: str, data_id: str) -> str:
        """Generate config key."""
        return f"{tenant}+{group}+{data_id}"

    def put(
        self,
        tenant: str,
        group: str,
        data_id: str,
        version_id: str,
        stable_version_id: str,
        md5: bytes,
    ) -> None:
        """Track canary version for a config."""
        key = self.config_key(tenant, group, data_id)
        self._versions[key] = CanaryVersion(
            version_id=version_id,
            stable_version_id=stable_version_id,
            md5=md5,
        )
        logger.debug(f"Canary version tracked for {key}: {version_id} (stable: {stable_version_id})")

    def get(self, tenant: str, group: str, data_id: str) -> CanaryVersion | None:
        """Get canary version info for a config."""
        key = self.config_key(tenant, group, data_id)
        return self._versions.get(key)

    def remove(self, tenant: str, group: str, data_id: str) -> None:
        """Remove canary version tracking for a config."""
        key = self.config_key(tenant, group, data_id)
        self._versions.pop(key, None)

    def on_canary_promoted(self, tenant: str, group: str, data_id: str) -> None:
        """Handle canary_promoted: promote canary to stable in local cache."""
        key = self.config_key(tenant, group, data_id)
        cv = self._versions.get(key)
        if cv:
            logger.info(f"Canary promoted for {key}, now stable")
            self._versions[key] = CanaryVersion(
                version_id=cv.version_id,
                stable_version_id=cv.version_id,  # Promote: stable = canary
                md5=cv.md5,
            )

    def on_canary_withdrawn(self, tenant: str, group: str, data_id: str) -> None:
        """Handle canary_withdrawn: invalidate canary version, revert to stable."""
        key = self.config_key(tenant, group, data_id)
        logger.info(f"Canary withdrawn for {key}, reverting to stable")
        self._versions.pop(key, None)

    def get_all(self) -> dict[str, CanaryVersion]:
        """Get all tracked canary versions."""
        return self._versions.copy()
