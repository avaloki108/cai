"""Lightweight cache helpers with LRU + optional TTL."""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Generic, Hashable, Optional, TypeVar


K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class LRUCache(Generic[K, V]):
    """Simple LRU cache with optional TTL (seconds)."""

    def __init__(self, max_size: int = 256, ttl_seconds: Optional[float] = None) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._data: OrderedDict[K, tuple[float, V]] = OrderedDict()

    def _expired(self, timestamp: float) -> bool:
        if self.ttl_seconds is None:
            return False
        return (time.time() - timestamp) > self.ttl_seconds

    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        item = self._data.get(key)
        if not item:
            return default
        ts, value = item
        if self._expired(ts):
            self._data.pop(key, None)
            return default
        # mark as recently used
        self._data.move_to_end(key)
        return value

    def set(self, key: K, value: V) -> None:
        self._data[key] = (time.time(), value)
        self._data.move_to_end(key)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def __contains__(self, key: object) -> bool:
        if key not in self._data:
            return False
        ts, _ = self._data[key]  # type: ignore[index]
        if self._expired(ts):
            self._data.pop(key, None)
            return False
        return True

    def __len__(self) -> int:
        return len(self._data)

    def items(self):
        """Return non-expired cache items."""
        expired_keys = []
        for key, (ts, value) in self._data.items():
            if self._expired(ts):
                expired_keys.append(key)
            else:
                yield key, value
        for key in expired_keys:
            self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()
