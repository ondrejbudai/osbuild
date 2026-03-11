#
# Integration tests for the fake xattr supervisor.
#
# These tests require unprivileged user namespace support.
#

import ctypes
import ctypes.util
import json
import os
import platform
import subprocess
import sys
import tempfile

import pytest

# Skip entire module if architecture is unsupported
_ARCH = platform.machine()
if _ARCH not in ("x86_64", "aarch64"):
    pytest.skip(f"Unsupported architecture: {_ARCH}", allow_module_level=True)


def _check_userns():
    """Check if unprivileged user namespaces are available."""
    try:
        r = subprocess.run(
            ["unshare", "--user", "--map-root-user", "true"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_HAS_USERNS = _check_userns()

pytestmark = pytest.mark.skipif(
    not _HAS_USERNS,
    reason="unprivileged user namespaces not available"
)


@pytest.fixture(name="tmpdir")
def tmpdir_fixture():
    with tempfile.TemporaryDirectory(dir="/var/tmp") as tmp:
        yield tmp


def _run_under_supervisor(cache_path, script, tmpdir):
    """Run a Python script under the fake xattr supervisor inside a user namespace.

    Returns (returncode, stdout, stderr, cache_data).
    """
    script_path = os.path.join(tmpdir, "test_script.py")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script)

    cmd = [
        "unshare", "--map-auto", "--map-root-user", "--",
        sys.executable, "-m", "osbuild.fake_xattr_supervisor",
        cache_path, "--",
        sys.executable, script_path,
    ]

    # Set PYTHONPATH so the supervisor and test script can find osbuild
    env = os.environ.copy()
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env["PYTHONPATH"] = project_root + ":" + env.get("PYTHONPATH", "")

    r = subprocess.run(cmd, capture_output=True, timeout=30, env=env)

    cache_data = {}
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            cache_data = json.load(f)

    return r.returncode, r.stdout.decode(), r.stderr.decode(), cache_data


class TestSupervisor:
    def test_setxattr(self, tmpdir):
        """Verify that lsetxattr for security.* populates the cache."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "testfile")

        # Create test file before entering the namespace
        with open(test_file, "w") as f:
            f.write("test")

        script = f"""
import ctypes
import ctypes.util
import os

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

path = b"{test_file}"
name = b"security.selinux"
value = b"system_u:object_r:usr_t:s0\\x00"

ret = libc.lsetxattr(path, name, value, len(value), 0)
err = ctypes.get_errno()
print(f"lsetxattr returned {{ret}}, errno={{err}}")
if ret != 0:
    raise SystemExit(1)
"""
        rc, stdout, stderr, cache_data = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert test_file in cache_data
        assert "security.selinux" in cache_data[test_file]

    def test_getxattr_roundtrip(self, tmpdir):
        """Set then get a security.selinux value under the supervisor."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "testfile")

        with open(test_file, "w") as f:
            f.write("test")

        script = f"""
import ctypes
import ctypes.util
import os

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

path = b"{test_file}"
name = b"security.selinux"
value = b"system_u:object_r:usr_t:s0\\x00"

# Set
ret = libc.lsetxattr(path, name, value, len(value), 0)
if ret != 0:
    print(f"lsetxattr failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(1)

# Get (size query first)
ret = libc.lgetxattr(path, name, None, 0)
if ret < 0:
    print(f"lgetxattr size query failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(2)

size = ret
buf = ctypes.create_string_buffer(size)
ret = libc.lgetxattr(path, name, buf, size)
if ret < 0:
    print(f"lgetxattr failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(3)

got = buf.raw[:ret]
if got != value:
    print(f"mismatch: got {{got!r}}, expected {{value!r}}")
    raise SystemExit(4)

print("roundtrip OK")
"""
        rc, stdout, stderr, _ = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert "roundtrip OK" in stdout

    def test_non_security_passthrough(self, tmpdir):
        """Verify that user.* xattr operations pass through to the kernel."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "testfile")

        with open(test_file, "w") as f:
            f.write("test")

        script = f"""
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

path = b"{test_file}"
name = b"user.test"
value = b"hello"

# user.* xattrs should work inside user namespaces via CONTINUE
ret = libc.lsetxattr(path, name, value, len(value), 0)
err = ctypes.get_errno()
if ret != 0:
    print(f"lsetxattr user.test failed: errno={{err}}")
    raise SystemExit(1)

buf = ctypes.create_string_buffer(256)
ret = libc.lgetxattr(path, name, buf, 256)
if ret < 0:
    print(f"lgetxattr user.test failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(2)

got = buf.raw[:ret]
if got != value:
    print(f"mismatch: got {{got!r}}, expected {{value!r}}")
    raise SystemExit(3)

print("passthrough OK")
"""
        rc, stdout, stderr, cache_data = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert "passthrough OK" in stdout
        # user.* should NOT appear in the cache
        for path_entry in cache_data.values():
            assert "user.test" not in path_entry

    def test_listxattr_merge(self, tmpdir):
        """Verify listxattr returns both real and cached names."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "testfile")

        with open(test_file, "w") as f:
            f.write("test")

        script = f"""
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

path = b"{test_file}"

# Set a user.* xattr (real)
ret = libc.lsetxattr(path, b"user.test", b"val", 3, 0)
if ret != 0:
    print(f"lsetxattr user.test failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(1)

# Set a security.* xattr (cached)
ret = libc.lsetxattr(path, b"security.selinux", b"label\\x00", 6, 0)
if ret != 0:
    print(f"lsetxattr security.selinux failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(2)

# List xattrs
buf = ctypes.create_string_buffer(4096)
ret = libc.llistxattr(path, buf, 4096)
if ret < 0:
    print(f"llistxattr failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(3)

# Parse the null-separated list
raw = buf.raw[:ret]
names = [n.decode() for n in raw.split(b"\\x00") if n]
print(f"names: {{names}}")

if "user.test" not in names:
    print("missing user.test")
    raise SystemExit(4)
if "security.selinux" not in names:
    print("missing security.selinux")
    raise SystemExit(5)

print("merge OK")
"""
        rc, stdout, stderr, _ = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert "merge OK" in stdout

    def test_removexattr(self, tmpdir):
        """Verify that removexattr removes a cached security.* xattr."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "testfile")

        with open(test_file, "w") as f:
            f.write("test")

        script = f"""
import ctypes
import ctypes.util
import errno as _errno

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

path = b"{test_file}"
name = b"security.selinux"
value = b"label\\x00"

# Set
ret = libc.lsetxattr(path, name, value, len(value), 0)
if ret != 0:
    print(f"lsetxattr failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(1)

# Verify it's set
ret = libc.lgetxattr(path, name, None, 0)
if ret < 0:
    print(f"lgetxattr failed after set: errno={{ctypes.get_errno()}}")
    raise SystemExit(2)

# Remove
ret = libc.lremovexattr(path, name)
if ret != 0:
    print(f"lremovexattr failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(3)

# Verify it's gone (should return ENODATA)
ret = libc.lgetxattr(path, name, None, 0)
if ret >= 0:
    print("lgetxattr succeeded after remove — should have failed")
    raise SystemExit(4)
err = ctypes.get_errno()
if err != _errno.ENODATA:
    print(f"expected ENODATA, got errno={{err}}")
    raise SystemExit(5)

print("removexattr OK")
"""
        rc, stdout, stderr, _ = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert "removexattr OK" in stdout

    def test_symlink_setxattr_follows(self, tmpdir):
        """Verify setxattr (follows symlinks) and lsetxattr use consistent cache keys."""
        cache_path = os.path.join(tmpdir, "cache.json")
        test_file = os.path.join(tmpdir, "realfile")
        test_link = os.path.join(tmpdir, "symlink")

        with open(test_file, "w") as f:
            f.write("test")
        os.symlink(test_file, test_link)

        script = f"""
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

link_path = b"{test_link}"
real_path = b"{test_file}"
name = b"security.selinux"
value = b"system_u:object_r:usr_t:s0\\x00"

# setxattr on the symlink — should follow and store under the real path
ret = libc.setxattr(link_path, name, value, len(value), 0)
if ret != 0:
    print(f"setxattr via symlink failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(1)

# lgetxattr on the real path — should find the cached value
ret = libc.lgetxattr(real_path, name, None, 0)
if ret < 0:
    print(f"lgetxattr on real path failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(2)

buf = ctypes.create_string_buffer(ret)
ret = libc.lgetxattr(real_path, name, buf, ret)
if ret < 0:
    print(f"lgetxattr read failed: errno={{ctypes.get_errno()}}")
    raise SystemExit(3)

got = buf.raw[:ret]
if got != value:
    print(f"mismatch: got {{got!r}}, expected {{value!r}}")
    raise SystemExit(4)

print("symlink OK")
"""
        rc, stdout, stderr, cache_data = _run_under_supervisor(cache_path, script, tmpdir)
        assert rc == 0, f"stdout={stdout}, stderr={stderr}"
        assert "symlink OK" in stdout
        # Cache should have the real path, not the symlink path
        assert test_file in cache_data
        assert test_link not in cache_data
