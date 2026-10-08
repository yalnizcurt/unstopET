"""Linux-only, irreversible agent restrictions. Missing kernel support fails closed."""
import ctypes
import os
from pathlib import Path
import resource
import sys
import sysconfig


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def restrict(read_files=()):
    if sys.platform != "linux":
        raise RuntimeError("Linux isolation unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    def number(name):
        value = lib.seccomp_syscall_resolve_name(name.encode())
        if value < 0:
            raise RuntimeError("Required syscall unavailable")
        return value
    def call(name, *args):
        result = libc.syscall(number(name), *args)
        if result < 0:
            raise RuntimeError("Required Linux isolation operation failed")
        return result

    abi = call("landlock_create_ruleset", None, 0, 1)
    if abi < 3:
        raise RuntimeError("Landlock ABI 3 or newer is required")
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError("Privilege isolation failed")
    attributes = Ruleset((1 << 15) - 1)  # All filesystem operations through ABI 3, including truncate.
    ruleset = call("landlock_create_ruleset", ctypes.byref(attributes), ctypes.sizeof(attributes), 0)
    try:
        for path in (sysconfig.get_path("stdlib"), str(Path(__file__).with_name("agent_runtime.py")), "/dev/urandom", *read_files):
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rights = (1 << 2) | ((1 << 3) if os.path.isdir(path) else 0)
                rule = PathRule(rights, descriptor)
                call("landlock_add_rule", ruleset, 1, ctypes.byref(rule), 0)
            finally:
                os.close(descriptor)
        call("landlock_restrict_self", ruleset, 0)
    finally:
        os.close(ruleset)

    # Default deny. No sockets, execution, process creation, namespace changes, ptrace,
    # process-memory reads, or new filesystem mutations exist in this allowlist.
    context = lib.seccomp_init(0x00050001)  # SCMP_ACT_ERRNO(EPERM)
    if not context:
        raise RuntimeError("Seccomp initialization failed")
    try:
        for name in (
            "read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "pread64",
            "openat", "readlink", "readlinkat", "getdents64", "fcntl", "ioctl", "dup", "dup2", "dup3",
            "mmap", "mprotect", "munmap", "mremap", "madvise", "brk",
            "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "futex",
            "clock_gettime", "gettimeofday", "nanosleep", "clock_nanosleep", "sched_yield",
            "getrandom", "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid", "uname",
            "poll", "ppoll", "select", "pselect6", "prlimit64", "getrlimit", "exit", "exit_group",
        ):
            syscall = lib.seccomp_syscall_resolve_name(name.encode())
            if syscall >= 0 and lib.seccomp_rule_add(context, 0x7FFF0000, syscall, 0) != 0:
                raise RuntimeError("Seccomp rule failed")
        if lib.seccomp_load(context) != 0:
            raise RuntimeError("Seccomp enforcement failed")
    finally:
        lib.seccomp_release(context)
