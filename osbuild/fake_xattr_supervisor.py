"""Fake xattr supervisor for rootless osbuild.

Invoked as: python3 -m osbuild.fake_xattr_supervisor <cache_path> -- <cmd...>

Uses seccomp user notification to intercept xattr syscalls and emulate
security.* xattrs via an in-memory cache backed by JSON. Non-security.*
xattr operations are passed through to the kernel via SECCOMP_USER_NOTIF_FLAG_CONTINUE.

Architecture:
  fork() before installing seccomp filter.
  Child: installs filter, sends notif_fd to parent via SCM_RIGHTS, execs cmd.
  Parent: receives notif_fd, handles notifications in a loop, waits for child.
"""

import array
import errno
import fcntl
import os
import platform
import select
import socket
import sys

from osbuild.util.fake_xattr import FakeXattrCache
from osbuild.util.seccomp import (
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    XATTR_SYSCALLS,
    SeccompNotifResp,
    build_xattr_filter,
    notif_id_valid,
    notif_recv,
    notif_send,
    seccomp_set_mode_filter_listener,
)

_ARCH = platform.machine()
_SYSCALL_TABLE = XATTR_SYSCALLS.get(_ARCH, {})

# Build reverse mapping: syscall_nr -> name
_NR_TO_NAME = {nr: name for name, nr in _SYSCALL_TABLE.items()}


def _read_proc_mem(pid, addr, length):
    """Read `length` bytes from target process memory at `addr`."""
    path = f"/proc/{pid}/mem"
    with open(path, "rb") as f:
        f.seek(addr)
        return f.read(length)


def _write_proc_mem(pid, addr, data):
    """Write `data` to target process memory at `addr`."""
    path = f"/proc/{pid}/mem"
    with open(path, "r+b") as f:
        f.seek(addr)
        f.write(data)


def _read_cstring(pid, addr, max_len=4096):
    """Read a null-terminated string from target process memory.

    Reads in page-aligned chunks to avoid crossing into unmapped memory.
    """
    result = b""
    remaining = max_len
    cur = addr
    page_size = 4096

    while remaining > 0:
        # Read up to the end of the current page
        offset_in_page = cur % page_size
        chunk_size = min(page_size - offset_in_page, remaining)
        try:
            chunk = _read_proc_mem(pid, cur, chunk_size)
        except OSError:
            break
        nul = chunk.find(b'\x00')
        if nul >= 0:
            result += chunk[:nul]
            break
        result += chunk
        cur += len(chunk)
        remaining -= len(chunk)
        if len(chunk) < chunk_size:
            break

    return result.decode("utf-8", errors="surrogateescape")


def _resolve_fd_path(pid, fd):
    """Resolve an fd in the target process to a path."""
    return os.readlink(f"/proc/{pid}/fd/{fd}")


def _abs_path(pid, path):
    """Make a path absolute using the target process's cwd.

    If path is already absolute, return as-is. Otherwise, resolve
    relative to /proc/<pid>/cwd.
    """
    if os.path.isabs(path):
        return path
    cwd = os.readlink(f"/proc/{pid}/cwd")
    return os.path.normpath(os.path.join(cwd, path))


def _cache_path(pid, path, follow_symlinks):
    """Get the cache key for a path, optionally resolving symlinks.

    setxattr(2) follows symlinks but lsetxattr(2) does not, and
    similarly for the other xattr syscalls. To ensure cache
    consistency, symlink-following variants resolve through
    /proc/<pid>/root so the cache key is the real target path.
    """
    if not follow_symlinks:
        return path
    proc_root = f"/proc/{pid}/root"
    proc_path = proc_root + path
    try:
        resolved = os.path.realpath(proc_path)
        # realpath resolves the /proc/<pid>/root magic symlink, so we
        # need to strip the target's real root to get an absolute path
        # in the target's namespace.
        root = os.path.realpath(proc_root)
        if root == "/":
            return resolved
        if resolved.startswith(root + "/"):
            return resolved[len(root):]
        if resolved == root:
            return "/"
    except OSError:
        pass
    return path


def _resolve_path(pid, path):
    """Resolve a path relative to the target process's root.

    Returns the path as seen from the supervisor's namespace via
    /proc/<pid>/root.
    """
    abspath = _abs_path(pid, path)
    return f"/proc/{pid}/root{abspath}"


def _is_security_xattr(name):
    """Check if an xattr name is in the security.* namespace."""
    return name.startswith("security.")


def _make_continue_resp(notif_id):
    """Create a CONTINUE response to let the kernel handle the syscall."""
    resp = SeccompNotifResp()
    resp.id = notif_id
    resp.val = 0
    resp.error = 0
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
    return resp


def _make_success_resp(notif_id, retval=0):
    """Create a success response with a given return value."""
    resp = SeccompNotifResp()
    resp.id = notif_id
    resp.val = retval
    resp.error = 0
    resp.flags = 0
    return resp


def _make_error_resp(notif_id, err):
    """Create an error response."""
    resp = SeccompNotifResp()
    resp.id = notif_id
    resp.val = 0
    resp.error = -err
    resp.flags = 0
    return resp


def handle_setxattr(notif, notif_fd, cache, follow_symlinks):
    """Handle setxattr/lsetxattr: args[0]=path, args[1]=name, args[2]=value, args[3]=size."""
    pid = notif.pid
    try:
        path = _abs_path(pid, _read_cstring(pid, notif.data.args[0]))
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None

    size = notif.data.args[3]

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    path = _cache_path(pid, path, follow_symlinks)
    try:
        value = _read_proc_mem(pid, notif.data.args[2], size) if size > 0 else b""
    except OSError:
        return None
    cache.setxattr(path, name, value)
    return _make_success_resp(notif.id)


def handle_fsetxattr(notif, notif_fd, cache, _follow_symlinks):
    """Handle fsetxattr: args[0]=fd, args[1]=name, args[2]=value, args[3]=size."""
    pid = notif.pid
    fd = notif.data.args[0]
    try:
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None
    size = notif.data.args[3]

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        path = _resolve_fd_path(pid, fd)
        value = _read_proc_mem(pid, notif.data.args[2], size) if size > 0 else b""
    except OSError:
        return None
    cache.setxattr(path, name, value)
    return _make_success_resp(notif.id)


def handle_getxattr(notif, notif_fd, cache, follow_symlinks):
    """Handle getxattr/lgetxattr: args[0]=path, args[1]=name, args[2]=value_buf, args[3]=size."""
    pid = notif.pid
    try:
        path = _abs_path(pid, _read_cstring(pid, notif.data.args[0]))
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    path = _cache_path(pid, path, follow_symlinks)
    try:
        value = cache.getxattr(path, name)
    except KeyError:
        return _make_error_resp(notif.id, errno.ENODATA)

    buf_size = notif.data.args[3]
    if buf_size == 0:
        # Size query: return the size of the value
        return _make_success_resp(notif.id, len(value))

    if len(value) > buf_size:
        return _make_error_resp(notif.id, errno.ERANGE)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        _write_proc_mem(pid, notif.data.args[2], value)
    except OSError:
        return None
    return _make_success_resp(notif.id, len(value))


def handle_fgetxattr(notif, notif_fd, cache, _follow_symlinks):
    """Handle fgetxattr: args[0]=fd, args[1]=name, args[2]=value_buf, args[3]=size."""
    pid = notif.pid
    fd = notif.data.args[0]
    try:
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        path = _resolve_fd_path(pid, fd)
    except OSError:
        return None

    try:
        value = cache.getxattr(path, name)
    except KeyError:
        return _make_error_resp(notif.id, errno.ENODATA)

    buf_size = notif.data.args[3]
    if buf_size == 0:
        return _make_success_resp(notif.id, len(value))

    if len(value) > buf_size:
        return _make_error_resp(notif.id, errno.ERANGE)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        _write_proc_mem(pid, notif.data.args[2], value)
    except OSError:
        return None
    return _make_success_resp(notif.id, len(value))


def handle_listxattr(notif, notif_fd, cache, follow_symlinks):
    """Handle listxattr/llistxattr: args[0]=path, args[1]=list_buf, args[2]=size.

    We cannot use CONTINUE because we need to merge real xattrs with cached
    security.* entries. Perform real listxattr via /proc/<pid>/root/<path>,
    then append cached names.
    """
    pid = notif.pid
    try:
        path = _abs_path(pid, _read_cstring(pid, notif.data.args[0]))
    except OSError:
        return None

    if not notif_id_valid(notif_fd, notif.id):
        return None

    path = _cache_path(pid, path, follow_symlinks)

    # Get real xattrs from the filesystem, filtering out security.*
    # names since those cannot be read inside user namespaces.
    # Only our cache is authoritative for security.* xattrs.
    real_path = _resolve_path(pid, path)
    try:
        real_names = [n for n in os.listxattr(real_path, follow_symlinks=False)
                      if not _is_security_xattr(n)]
    except OSError:
        real_names = []

    # Get cached names (security.* namespace)
    cached_names = cache.listxattr(path)

    # Merge: real names + cached names
    all_names = list(real_names) + cached_names

    # Build the null-terminated list
    result = b"".join(n.encode("utf-8") + b"\x00" for n in all_names)

    buf_size = notif.data.args[2]
    if buf_size == 0:
        return _make_success_resp(notif.id, len(result))

    if len(result) > buf_size:
        return _make_error_resp(notif.id, errno.ERANGE)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        _write_proc_mem(pid, notif.data.args[1], result)
    except OSError:
        return None
    return _make_success_resp(notif.id, len(result))


def handle_flistxattr(notif, notif_fd, cache, _follow_symlinks):
    """Handle flistxattr: args[0]=fd, args[1]=list_buf, args[2]=size."""
    pid = notif.pid
    fd = notif.data.args[0]

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        path = _resolve_fd_path(pid, fd)
    except OSError:
        return None

    # Get real xattrs, filtering out security.* (same rationale as above)
    try:
        real_names = [n for n in os.listxattr(f"/proc/{pid}/fd/{fd}", follow_symlinks=False)
                      if not _is_security_xattr(n)]
    except OSError:
        real_names = []

    cached_names = cache.listxattr(path)

    all_names = list(real_names) + cached_names

    result = b"".join(n.encode("utf-8") + b"\x00" for n in all_names)

    buf_size = notif.data.args[2]
    if buf_size == 0:
        return _make_success_resp(notif.id, len(result))

    if len(result) > buf_size:
        return _make_error_resp(notif.id, errno.ERANGE)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        _write_proc_mem(pid, notif.data.args[1], result)
    except OSError:
        return None
    return _make_success_resp(notif.id, len(result))


def handle_removexattr(notif, notif_fd, cache, follow_symlinks):
    """Handle removexattr/lremovexattr: args[0]=path, args[1]=name."""
    pid = notif.pid
    try:
        path = _abs_path(pid, _read_cstring(pid, notif.data.args[0]))
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    path = _cache_path(pid, path, follow_symlinks)
    try:
        cache.removexattr(path, name)
    except KeyError:
        return _make_error_resp(notif.id, errno.ENODATA)
    return _make_success_resp(notif.id)


def handle_fremovexattr(notif, notif_fd, cache, _follow_symlinks):
    """Handle fremovexattr: args[0]=fd, args[1]=name."""
    pid = notif.pid
    fd = notif.data.args[0]
    try:
        name = _read_cstring(pid, notif.data.args[1])
    except OSError:
        return None

    if not _is_security_xattr(name):
        return _make_continue_resp(notif.id)

    if not notif_id_valid(notif_fd, notif.id):
        return None

    try:
        path = _resolve_fd_path(pid, fd)
    except OSError:
        return None
    try:
        cache.removexattr(path, name)
    except KeyError:
        return _make_error_resp(notif.id, errno.ENODATA)
    return _make_success_resp(notif.id)


# Dispatch table: syscall_name -> (handler, follow_symlinks)
# The l-prefixed variants (lsetxattr, lgetxattr, ...) do NOT follow symlinks,
# while the unprefixed variants (setxattr, getxattr, ...) DO follow them.
# fd-based variants don't need symlink handling (the kernel already resolved
# the fd to a real path), so follow_symlinks is False (unused).
_HANDLERS = {
    "setxattr":       (handle_setxattr, True),
    "lsetxattr":      (handle_setxattr, False),
    "fsetxattr":      (handle_fsetxattr, False),
    "getxattr":       (handle_getxattr, True),
    "lgetxattr":      (handle_getxattr, False),
    "fgetxattr":      (handle_fgetxattr, False),
    "listxattr":      (handle_listxattr, True),
    "llistxattr":     (handle_listxattr, False),
    "flistxattr":     (handle_flistxattr, False),
    "removexattr":    (handle_removexattr, True),
    "lremovexattr":   (handle_removexattr, False),
    "fremovexattr":   (handle_fremovexattr, False),
}


def handle_one_notification(notif_fd, cache):
    """Receive and handle one seccomp notification.

    Returns True to continue the loop, False on EOF/error.
    """
    try:
        notif = notif_recv(notif_fd)
    except OSError as e:
        if e.errno == errno.ENOENT:
            # Target process has died
            return True
        # EBADF or similar means the notif_fd was closed
        return False

    syscall_name = _NR_TO_NAME.get(notif.data.nr)
    if syscall_name is None:
        # Unknown syscall — should not happen, but allow it
        resp = _make_continue_resp(notif.id)
    else:
        entry = _HANDLERS.get(syscall_name)
        if entry is None:
            resp = _make_continue_resp(notif.id)
        else:
            handler, follow_symlinks = entry
            resp = handler(notif, notif_fd, cache, follow_symlinks)

    if resp is not None:
        try:
            notif_send(notif_fd, resp)
        except OSError as e:
            if e.errno == errno.ENOENT:
                # Target has died or been interrupted, notification is gone
                pass
            else:
                raise

    return True


def _send_fd(sock, fd):
    """Send a file descriptor over a Unix socket via SCM_RIGHTS."""
    fds = array.array("i", [fd])
    sock.sendmsg(
        [b"\x00"],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)]
    )


def _recv_fd(sock):
    """Receive a file descriptor from a Unix socket via SCM_RIGHTS."""
    fds_size = array.array("i").itemsize
    msg, ancdata, _, _ = sock.recvmsg(
        1,
        socket.CMSG_SPACE(fds_size)
    )
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            received = array.array("i")
            received.frombytes(cmsg_data[:fds_size])
            return received[0]
    raise RuntimeError("Did not receive fd via SCM_RIGHTS")


def _extract_exit_status(status):
    """Extract exit code from waitpid status."""
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Parse: <cache_path> -- <cmd...>
    if "--" not in argv:
        print("Usage: python3 -m osbuild.fake_xattr_supervisor <cache_path> -- <cmd...>",
              file=sys.stderr)
        return 1

    sep = argv.index("--")
    if sep != 1:
        print("Usage: python3 -m osbuild.fake_xattr_supervisor <cache_path> -- <cmd...>",
              file=sys.stderr)
        return 1
    cache_path = argv[0]
    cmd = argv[sep + 1:]

    if not cmd:
        print("No command specified", file=sys.stderr)
        return 1

    cache = FakeXattrCache(cache_path)
    cache.load()

    # Create socket pair for sending notif_fd from child to parent
    parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    pid = os.fork()
    if pid == 0:
        # --- Child process ---
        parent_sock.close()
        try:
            # Install seccomp filter and get notif_fd
            bpf = build_xattr_filter()
            notif_fd = seccomp_set_mode_filter_listener(bpf)

            # Send notif_fd to parent
            _send_fd(child_sock, notif_fd)
            os.close(notif_fd)
            child_sock.close()

            # Exec the command
            os.execvp(cmd[0], cmd)
        except Exception as e:
            print(f"fake_xattr_supervisor child error: {e}", file=sys.stderr)
            os._exit(1)
    else:
        # --- Parent process ---
        child_sock.close()

        # Receive notif_fd from child
        notif_fd = _recv_fd(parent_sock)
        parent_sock.close()

        # Handle notifications until child exits.
        # Use poll() on notif_fd to avoid blocking forever when child
        # exits with no pending notifications.
        exit_status = 1
        poller = select.poll()
        poller.register(notif_fd, select.POLLIN)

        while True:
            events = poller.poll(100)  # 100ms timeout

            if events:
                for _, event in events:
                    if event & (select.POLLHUP | select.POLLERR):
                        # notif_fd hung up — child process tree is gone
                        break
                else:
                    # Normal POLLIN — handle notification
                    if not handle_one_notification(notif_fd, cache):
                        break
                    # Check child after handling
                    wpid, status = os.waitpid(pid, os.WNOHANG)
                    if wpid != 0:
                        exit_status = _extract_exit_status(status)
                        break
                    continue
                # Fell through from POLLHUP/POLLERR break
                break

            # No events (timeout) — check if child has exited
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid != 0:
                exit_status = _extract_exit_status(status)
                # Drain remaining notifications non-blocking
                flags = fcntl.fcntl(notif_fd, fcntl.F_GETFL)
                fcntl.fcntl(notif_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                try:
                    while handle_one_notification(notif_fd, cache):
                        pass
                except OSError:
                    pass
                break

        # If we broke out without collecting child, do so now
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid != 0:
                exit_status = _extract_exit_status(status)
        except ChildProcessError:
            pass

        # If child still not reaped (shouldn't happen normally), block-wait
        if exit_status == 1:
            try:
                _, status = os.waitpid(pid, 0)
                exit_status = _extract_exit_status(status)
            except ChildProcessError:
                pass

        poller.unregister(notif_fd)
        os.close(notif_fd)
        cache.save()
        return exit_status


if __name__ == "__main__":
    sys.exit(main())
