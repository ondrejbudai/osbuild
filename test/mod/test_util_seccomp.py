#
# Tests for the `osbuild.util.seccomp` module.
#

import ctypes
import struct

import pytest

from osbuild.util import seccomp


@pytest.mark.parametrize("arch,expected_range", [
    ("x86_64", (188, 199)),
    ("aarch64", (5, 16)),
])
def test_syscall_range(arch, expected_range):
    first, last = seccomp.get_xattr_syscall_range(arch)
    assert (first, last) == expected_range
    # Verify the range covers exactly 12 syscalls (contiguous)
    table = seccomp.XATTR_SYSCALLS[arch]
    assert len(table) == 12
    assert set(table.values()) == set(range(first, last + 1))


def test_syscall_range_unsupported():
    with pytest.raises(ValueError, match="Unsupported"):
        seccomp.get_xattr_syscall_range("sparc64")


@pytest.mark.parametrize("arch,expected_audit_arch", [
    ("x86_64", seccomp.AUDIT_ARCH_X86_64),
    ("aarch64", seccomp.AUDIT_ARCH_AARCH64),
])
def test_audit_arch(arch, expected_audit_arch):
    assert seccomp.get_audit_arch(arch) == expected_audit_arch


def test_audit_arch_unsupported():
    with pytest.raises(ValueError, match="Unsupported"):
        seccomp.get_audit_arch("sparc64")


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_syscall_nr_to_name(arch):
    table = seccomp.XATTR_SYSCALLS[arch]
    for name, nr in table.items():
        assert seccomp.syscall_nr_to_name(arch, nr) == name
    # Unknown syscall number
    assert seccomp.syscall_nr_to_name(arch, 99999) is None


class TestStructSizes:
    def test_seccomp_data(self):
        assert ctypes.sizeof(seccomp.SeccompData) == 64

    def test_seccomp_notif(self):
        assert ctypes.sizeof(seccomp.SeccompNotif) == 80

    def test_seccomp_notif_resp(self):
        assert ctypes.sizeof(seccomp.SeccompNotifResp) == 24


class TestIoctlConstants:
    def test_notif_recv(self):
        assert seccomp.SECCOMP_IOCTL_NOTIF_RECV == 0xC0502100

    def test_notif_send(self):
        assert seccomp.SECCOMP_IOCTL_NOTIF_SEND == 0xC0182101

    def test_notif_id_valid(self):
        assert seccomp.SECCOMP_IOCTL_NOTIF_ID_VALID == 0x40082102


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_bpf_filter_construction(arch):
    bpf = seccomp.build_xattr_filter(arch)
    # Each BPF instruction is 8 bytes, expect 7 instructions
    assert len(bpf) == 7 * 8

    # Parse instructions
    instructions = []
    for i in range(7):
        code, jt, jf, k = struct.unpack("HBBI", bpf[i*8:(i+1)*8])
        instructions.append((code, jt, jf, k))

    # Instruction 0: LD arch
    assert instructions[0][0] == (seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS)
    assert instructions[0][3] == 4  # offset of arch in seccomp_data

    # Instruction 1: JEQ audit_arch
    assert instructions[1][0] == (seccomp.BPF_JMP | seccomp.BPF_JEQ | seccomp.BPF_K)
    assert instructions[1][3] == seccomp.get_audit_arch(arch)

    # Instruction 2: LD syscall_nr
    assert instructions[2][0] == (seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS)
    assert instructions[2][3] == 0  # offset of nr in seccomp_data

    # Instruction 3: JGE first_xattr_nr
    first_nr, _ = seccomp.get_xattr_syscall_range(arch)
    assert instructions[3][0] == (seccomp.BPF_JMP | seccomp.BPF_JGE | seccomp.BPF_K)
    assert instructions[3][3] == first_nr

    # Instruction 4: JGT last_xattr_nr
    _, last_nr = seccomp.get_xattr_syscall_range(arch)
    assert instructions[4][0] == (seccomp.BPF_JMP | seccomp.BPF_JGT | seccomp.BPF_K)
    assert instructions[4][3] == last_nr

    # Instruction 5: RET USER_NOTIF
    assert instructions[5][0] == (seccomp.BPF_RET | seccomp.BPF_K)
    assert instructions[5][3] == seccomp.SECCOMP_RET_USER_NOTIF

    # Instruction 6: RET ALLOW
    assert instructions[6][0] == (seccomp.BPF_RET | seccomp.BPF_K)
    assert instructions[6][3] == seccomp.SECCOMP_RET_ALLOW


@pytest.mark.parametrize("arch,expected", [
    ("x86_64", True),
    ("aarch64", True),
    ("s390x", False),
    ("ppc64le", False),
])
def test_is_supported_arch(arch, expected):
    assert seccomp.is_supported_arch(arch) == expected
