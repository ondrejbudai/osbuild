"""Fake Extended Attribute Cache

Provides an in-memory cache for security.* xattrs that cannot be set inside
user namespaces. The cache is persisted as JSON and shared across pipeline
stages.
"""

import json
import os
import tempfile


class FakeXattrCache:
    """In-memory cache for extended attributes with JSON persistence.

    Keys are absolute paths inside the container.
    Values are dicts mapping xattr names to hex-encoded values.
    """

    def __init__(self, path=None):
        self._path = path
        self._cache = {}

    def setxattr(self, filepath, name, value):
        """Store an xattr value. `value` should be bytes."""
        if filepath not in self._cache:
            self._cache[filepath] = {}
        self._cache[filepath][name] = value.hex()

    def getxattr(self, filepath, name):
        """Retrieve an xattr value as bytes. Raises KeyError if not found."""
        entry = self._cache.get(filepath)
        if entry is None or name not in entry:
            raise KeyError(f"No xattr {name!r} for {filepath!r}")
        return bytes.fromhex(entry[name])

    def listxattr(self, filepath):
        """Return list of cached xattr names for a path."""
        entry = self._cache.get(filepath)
        if entry is None:
            return []
        return list(entry.keys())

    def removexattr(self, filepath, name):
        """Remove a cached xattr. Raises KeyError if not found."""
        entry = self._cache.get(filepath)
        if entry is None or name not in entry:
            raise KeyError(f"No xattr {name!r} for {filepath!r}")
        del entry[name]
        if not entry:
            del self._cache[filepath]

    def save(self, path=None):
        """Save cache to JSON file using atomic write (temp file + rename)."""
        path = path or self._path
        if path is None:
            raise ValueError("No path specified for save")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        dirpath = os.path.dirname(path)
        fd, tmp = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise

    def load(self, path=None):
        """Load cache from JSON file. Silently starts empty if file missing."""
        path = path or self._path
        if path is None:
            raise ValueError("No path specified for load")
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._cache = json.load(f)
        except FileNotFoundError:
            self._cache = {}
