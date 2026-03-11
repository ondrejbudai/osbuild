"""Seccomp User Notification Infrastructure

Low-level seccomp constants, ctypes structures, BPF filter builder, and
syscall wrappers for intercepting xattr syscalls via SECCOMP_RET_USER_NOTIF.
"""

import ctypes
import ctypes.util
import errno
import fcntl
import platform
import struct

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------

# Audit arch constants (from <linux/audit.h>)
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

_MACHINE = platform.machine()

if _MACHINE == "x86_64":
    _AUDIT_ARCH = AUDIT_ARCH_X86_64
elif _MACHINE == "aarch64":
    _AUDIT_ARCH = AUDIT_ARCH_AARCH64
else:
    _AUDIT_ARCH = None

# Supported architectures — callers should check this before using seccomp
# features, since s390x and ppc64le are not yet supported.
SUPPORTED_ARCHES = frozenset(("x86_64", "aarch64"))


def is_supported_arch(arch=None):
    """Check if the given architecture supports seccomp xattr interception."""
    if arch is None:
        arch = _MACHINE
    return arch in SUPPORTED_ARCHES


# ---------------------------------------------------------------------------
# Syscall numbers per architecture
# ---------------------------------------------------------------------------

# xattr syscalls are contiguous on both x86_64 and aarch64
XATTR_SYSCALLS = {
    "x86_64": {
        "setxattr": 188,
        "lsetxattr": 189,
        "fsetxattr": 190,
        "getxattr": 191,
        "lgetxattr": 192,
        "fgetxattr": 193,
        "listxattr": 194,
        "llistxattr": 195,
        "flistxattr": 196,
        "removexattr": 197,
        "lremovexattr": 198,
        "fremovexattr": 199,
    },
    "aarch64": {
        "setxattr": 5,
        "lsetxattr": 6,
        "fsetxattr": 7,
        "getxattr": 8,
        "lgetxattr": 9,
        "fgetxattr": 10,
        "listxattr": 11,
        "llistxattr": 12,
        "flistxattr": 13,
        "removexattr": 14,
        "lremovexattr": 15,
        "fremovexattr": 16,
    },
}


def get_xattr_syscall_range(arch):
    """Return (first_nr, last_nr) for xattr syscalls on the given arch."""
    table = XATTR_SYSCALLS.get(arch)
    if table is None:
        raise ValueError(f"Unsupported architecture: {arch}")
    nrs = table.values()
    return min(nrs), max(nrs)


def get_audit_arch(arch):
    """Return AUDIT_ARCH_* constant for the given arch string."""
    mapping = {
        "x86_64": AUDIT_ARCH_X86_64,
        "aarch64": AUDIT_ARCH_AARCH64,
    }
    val = mapping.get(arch)
    if val is None:
        raise ValueError(f"Unsupported architecture: {arch}")
    return val


def syscall_nr_to_name(arch, nr):
    """Map a syscall number back to its name for the given arch."""
    table = XATTR_SYSCALLS.get(arch)
    if table is None:
        raise ValueError(f"Unsupported architecture: {arch}")
    for name, n in table.items():
        if n == nr:
            return name
    return None


# ---------------------------------------------------------------------------
# Seccomp constants
# ---------------------------------------------------------------------------

SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = (1 << 3)

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_USER_NOTIF = 0x7FC00000

SECCOMP_USER_NOTIF_FLAG_CONTINUE = (1 << 0)

# ---------------------------------------------------------------------------
# ioctl constants (computed from _IOC macro)
# ---------------------------------------------------------------------------

# _IOC(dir, type, nr, size)
# dir: _IOC_WRITE=1, _IOC_READ=2
# type: '!' = 0x21
# On x86_64/aarch64: _IOC_SIZEBITS=14, _IOC_DIRBITS=2
#   _IOC_NRSHIFT=0, _IOC_TYPESHIFT=8, _IOC_SIZESHIFT=16, _IOC_DIRSHIFT=30


def _ioc(direction, ioc_type, nr, size):
    return (direction << 30) | (ioc_type << 8) | (nr << 0) | (size << 16)


_IOC_WRITE = 1
_IOC_READ = 2

# SECCOMP_IOCTL_NOTIF_RECV = _IOWR('!', 0, struct seccomp_notif)  size=80
SECCOMP_IOCTL_NOTIF_RECV = _ioc(_IOC_READ | _IOC_WRITE, 0x21, 0, 80)
# SECCOMP_IOCTL_NOTIF_SEND = _IOWR('!', 1, struct seccomp_notif_resp)  size=24
SECCOMP_IOCTL_NOTIF_SEND = _ioc(_IOC_READ | _IOC_WRITE, 0x21, 1, 24)
# SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW('!', 2, __u64)  size=8
SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(_IOC_WRITE, 0x21, 2, 8)

# ---------------------------------------------------------------------------
# Ctypes structures (mirroring kernel headers)
# ---------------------------------------------------------------------------


class SeccompData(ctypes.Structure):
    """struct seccomp_data — 64 bytes"""
    _fields_ = [
        ("nr", ctypes.c_int32),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class SeccompNotif(ctypes.Structure):
    """struct seccomp_notif — 80 bytes"""
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", SeccompData),
    ]


class SeccompNotifResp(ctypes.Structure):
    """struct seccomp_notif_resp — 24 bytes"""
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    """struct sock_fprog"""
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# BPF filter builder
# ---------------------------------------------------------------------------

# BPF instruction encoding: struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
_BPF_FMT = "HBBI"

# BPF opcodes
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JGE = 0x30
BPF_JGT = 0x20
BPF_RET = 0x06
BPF_K = 0x00

# Offsets into struct seccomp_data
_OFFSET_NR = 0      # offsetof(struct seccomp_data, nr)
_OFFSET_ARCH = 4    # offsetof(struct seccomp_data, arch)


def _bpf_stmt(code, k):
    return struct.pack(_BPF_FMT, code, 0, 0, k)


def _bpf_jump(code, k, jt, jf):
    return struct.pack(_BPF_FMT, code, jt, jf, k)


def build_xattr_filter(arch=None):
    """Build a BPF filter that intercepts xattr syscalls via USER_NOTIF.

    Returns raw bytes suitable for use with seccomp().

    The filter is a 7-instruction program:
      0: LD arch
      1: JEQ audit_arch -> 2, else -> 6 (ALLOW)
      2: LD syscall_nr
      3: JGE first_xattr_nr -> 4, else -> 6 (ALLOW)
      4: JGT last_xattr_nr -> 6 (ALLOW), else -> 5
      5: RET USER_NOTIF
      6: RET ALLOW
    """
    if arch is None:
        arch = _MACHINE

    audit_arch = get_audit_arch(arch)
    first_nr, last_nr = get_xattr_syscall_range(arch)

    instructions = [
        # 0: Load architecture
        _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, _OFFSET_ARCH),
        # 1: Check architecture (if match jump to 2, else jump to 6=ALLOW)
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 0, 4),
        # 2: Load syscall number
        _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, _OFFSET_NR),
        # 3: syscall_nr >= first_xattr? (yes->4, no->6=ALLOW)
        _bpf_jump(BPF_JMP | BPF_JGE | BPF_K, first_nr, 0, 2),
        # 4: syscall_nr > last_xattr? (yes->6=ALLOW, no->5=USER_NOTIF)
        _bpf_jump(BPF_JMP | BPF_JGT | BPF_K, last_nr, 1, 0),
        # 5: Return USER_NOTIF
        _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        # 6: Return ALLOW
        _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ]

    return b"".join(instructions)


# ---------------------------------------------------------------------------
# Syscall wrappers
# ---------------------------------------------------------------------------

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_NR_SECCOMP = {"x86_64": 317, "aarch64": 277}.get(_MACHINE)


def seccomp_set_mode_filter_listener(bpf_bytes):
    """Install a seccomp filter with SECCOMP_FILTER_FLAG_NEW_LISTENER.

    Returns the notification fd.
    Raises RuntimeError on unsupported architectures.
    """
    if _NR_SECCOMP is None:
        raise RuntimeError(f"seccomp syscall number not known for {_MACHINE}")
    n_instructions = len(bpf_bytes) // 8
    filter_buf = ctypes.create_string_buffer(bpf_bytes)
    fprog = SockFprog()
    fprog.len = n_instructions
    fprog.filter = ctypes.addressof(filter_buf)

    # We must keep filter_buf alive during the syscall
    ret = _libc.syscall(
        ctypes.c_long(_NR_SECCOMP),
        ctypes.c_ulong(SECCOMP_SET_MODE_FILTER),
        ctypes.c_ulong(SECCOMP_FILTER_FLAG_NEW_LISTENER),
        ctypes.byref(fprog),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"seccomp(SET_MODE_FILTER): {errno.errorcode.get(err, err)}")
    return ret


def notif_recv(notif_fd):
    """Receive a seccomp notification. Returns a SeccompNotif."""
    notif = SeccompNotif()
    fcntl.ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, notif)
    return notif


def notif_send(notif_fd, resp):
    """Send a seccomp notification response."""
    fcntl.ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, resp)


def notif_id_valid(notif_fd, notif_id):
    """Check if a notification ID is still valid (TOCTOU check).

    Returns True if valid, False if the target has died/been interrupted.
    """
    buf = struct.pack("Q", notif_id)
    try:
        fcntl.ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, buf)
        return True
    except OSError:
        return False
