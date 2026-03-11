#
# Tests for the `osbuild.util.fake_xattr` module.
#

import json
import os
import tempfile

import pytest

from osbuild.util.fake_xattr import FakeXattrCache


@pytest.fixture(name="tmpdir")
def tmpdir_fixture():
    with tempfile.TemporaryDirectory(dir="/var/tmp") as tmp:
        yield tmp


@pytest.fixture(name="cache_path")
def cache_path_fixture(tmpdir):
    return os.path.join(tmpdir, "meta", "fake_xattrs.json")


class TestFakeXattrCache:
    def test_set_get(self):
        cache = FakeXattrCache()
        value = b"system_u:object_r:usr_t:s0\x00"
        cache.setxattr("/usr/bin/bash", "security.selinux", value)
        assert cache.getxattr("/usr/bin/bash", "security.selinux") == value

    def test_get_missing_path(self):
        cache = FakeXattrCache()
        with pytest.raises(KeyError):
            cache.getxattr("/nonexistent", "security.selinux")

    def test_get_missing_name(self):
        cache = FakeXattrCache()
        cache.setxattr("/usr/bin/bash", "security.selinux", b"value")
        with pytest.raises(KeyError):
            cache.getxattr("/usr/bin/bash", "security.ima")

    def test_persistence(self, cache_path):
        value = b"system_u:object_r:bin_t:s0\x00"
        cache1 = FakeXattrCache(cache_path)
        cache1.setxattr("/usr/bin/ls", "security.selinux", value)
        cache1.save()

        cache2 = FakeXattrCache(cache_path)
        cache2.load()
        assert cache2.getxattr("/usr/bin/ls", "security.selinux") == value

    def test_listxattr(self):
        cache = FakeXattrCache()
        cache.setxattr("/file", "security.selinux", b"label1")
        cache.setxattr("/file", "security.ima", b"hash1")
        names = cache.listxattr("/file")
        assert set(names) == {"security.selinux", "security.ima"}

    def test_listxattr_empty(self):
        cache = FakeXattrCache()
        assert cache.listxattr("/nonexistent") == []

    def test_removexattr(self):
        cache = FakeXattrCache()
        cache.setxattr("/file", "security.selinux", b"label")
        cache.removexattr("/file", "security.selinux")
        with pytest.raises(KeyError):
            cache.getxattr("/file", "security.selinux")
        # Path should be cleaned up too
        assert cache.listxattr("/file") == []

    def test_removexattr_missing(self):
        cache = FakeXattrCache()
        with pytest.raises(KeyError):
            cache.removexattr("/nonexistent", "security.selinux")

    def test_overwrite(self):
        cache = FakeXattrCache()
        cache.setxattr("/file", "security.selinux", b"old")
        cache.setxattr("/file", "security.selinux", b"new")
        assert cache.getxattr("/file", "security.selinux") == b"new"

    def test_atomic_write(self, cache_path):
        cache = FakeXattrCache(cache_path)
        cache.setxattr("/file", "security.selinux", b"label")
        cache.save()

        # Verify the file exists and is valid JSON
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "/file" in data
        assert "security.selinux" in data["/file"]

    def test_load_missing_file(self, tmpdir):
        path = os.path.join(tmpdir, "nonexistent.json")
        cache = FakeXattrCache(path)
        cache.load()  # Should not raise
        assert cache.listxattr("/anything") == []

    def test_save_no_path(self):
        cache = FakeXattrCache()
        with pytest.raises(ValueError, match="No path"):
            cache.save()

    def test_load_no_path(self):
        cache = FakeXattrCache()
        with pytest.raises(ValueError, match="No path"):
            cache.load()
