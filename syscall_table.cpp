// ============================================================
//  syscall_table.cpp
//
//  Contributor : 24k-0791  Shahnawaz Khuwaja
//  Responsible : Syscall Table Mapping, Argument Parsing
//
//  What this file owns:
//    • SYSCALL_NAMES  — maps syscall number → human name
//    • ERRNO_NAMES    — maps errno number  → symbol name
//    • read_tracee_string() — safely read a C-string from the
//        tracee's address space via PTRACE_PEEKDATA
//    • format_arg()   — decode a raw register value into a
//        human-readable argument string (paths, fds, hex, etc.)
//    • format_errno() — turn a negative retval into "ENOENT" etc.
//    • syscall_argcount() — how many args to show for each call
//
//  GitHub commit scope: ONLY edit this file for anything related
//  to syscall names, argument decoding, or error symbol lookup.
// ============================================================

#include "sys_trace.h"

// ============================================================
//  Syscall number → name  (x86_64 Linux ABI)
//  Source: /usr/include/asm/unistd_64.h
// ============================================================
static const std::unordered_map<long, std::string> SYSCALL_NAMES = {
    {0,   "read"},         {1,   "write"},        {2,   "open"},
    {3,   "close"},        {4,   "stat"},         {5,   "fstat"},
    {6,   "lstat"},        {7,   "poll"},         {8,   "lseek"},
    {9,   "mmap"},         {10,  "mprotect"},     {11,  "munmap"},
    {12,  "brk"},          {13,  "rt_sigaction"}, {14,  "rt_sigprocmask"},
    {15,  "rt_sigreturn"}, {16,  "ioctl"},        {17,  "pread64"},
    {18,  "pwrite64"},     {19,  "readv"},        {20,  "writev"},
    {21,  "access"},       {22,  "pipe"},         {23,  "select"},
    {24,  "sched_yield"},  {25,  "mremap"},       {26,  "msync"},
    {27,  "mincore"},      {28,  "madvise"},      {29,  "shmget"},
    {32,  "dup"},          {33,  "dup2"},         {34,  "pause"},
    {35,  "nanosleep"},    {36,  "getitimer"},    {39,  "getpid"},
    {41,  "socket"},       {42,  "connect"},      {43,  "accept"},
    {44,  "sendto"},       {45,  "recvfrom"},     {46,  "sendmsg"},
    {47,  "recvmsg"},      {48,  "shutdown"},     {49,  "bind"},
    {50,  "listen"},       {51,  "getsockname"},  {52,  "getpeername"},
    {53,  "socketpair"},   {54,  "setsockopt"},   {55,  "getsockopt"},
    {56,  "clone"},        {57,  "fork"},         {58,  "vfork"},
    {59,  "execve"},       {60,  "exit"},         {61,  "wait4"},
    {62,  "kill"},         {63,  "uname"},        {72,  "fcntl"},
    {73,  "flock"},        {74,  "fsync"},        {75,  "fdatasync"},
    {76,  "truncate"},     {77,  "ftruncate"},    {78,  "getdents"},
    {79,  "getcwd"},       {80,  "chdir"},        {81,  "fchdir"},
    {82,  "rename"},       {83,  "mkdir"},        {84,  "rmdir"},
    {85,  "creat"},        {86,  "link"},         {87,  "unlink"},
    {88,  "symlink"},      {89,  "readlink"},     {90,  "chmod"},
    {91,  "fchmod"},       {92,  "chown"},        {93,  "fchown"},
    {94,  "lchown"},       {95,  "umask"},        {96,  "gettimeofday"},
    {97,  "getrlimit"},    {98,  "getrusage"},    {99,  "sysinfo"},
    {100, "times"},        {102, "getuid"},       {104, "getgid"},
    {105, "setuid"},       {106, "setgid"},       {107, "geteuid"},
    {108, "getegid"},      {110, "getppid"},      {111, "getpgrp"},
    {112, "setsid"},       {131, "sigaltstack"},  {132, "utime"},
    {137, "statfs"},       {138, "fstatfs"},      {157, "prctl"},
    {158, "arch_prctl"},   {160, "setrlimit"},    {161, "chroot"},
    {186, "gettid"},       {202, "futex"},        {217, "getdents64"},
    {218, "set_tid_address"}, {231, "exit_group"},{257, "openat"},
    {258, "mkdirat"},      {262, "newfstatat"},   {263, "unlinkat"},
    {264, "renameat"},     {267, "readlinkat"},   {269, "faccessat"},
    {270, "pselect6"},     {271, "ppoll"},        {273, "set_robust_list"},
    {274, "get_robust_list"}, {290, "eventfd2"},  {291, "epoll_create1"},
    {292, "dup3"},         {293, "pipe2"},        {302, "prlimit64"},
    {316, "renameat2"},    {318, "getrandom"},    {334, "rseq"},
};

// ============================================================
//  errno number → symbol name
// ============================================================
static const std::unordered_map<long, std::string> ERRNO_NAMES = {
    {1,   "EPERM"},   {2,  "ENOENT"}, {3,  "ESRCH"},   {4,  "EINTR"},
    {5,   "EIO"},     {6,  "ENXIO"},  {7,  "E2BIG"},   {8,  "ENOEXEC"},
    {9,   "EBADF"},   {11, "EAGAIN"}, {12, "ENOMEM"},  {13, "EACCES"},
    {14,  "EFAULT"},  {16, "EBUSY"},  {17, "EEXIST"},  {20, "ENOTDIR"},
    {21,  "EISDIR"},  {22, "EINVAL"}, {23, "ENFILE"},  {24, "EMFILE"},
    {25,  "ENOTTY"},  {28, "ENOSPC"}, {32, "EPIPE"},   {36, "ENAMETOOLONG"},
    {38,  "ENOSYS"},  {39, "ENOTEMPTY"},
    {110, "ETIMEDOUT"}, {111, "ECONNREFUSED"},
};

// ============================================================
//  Known arg-count table  (how many registers to display)
// ============================================================
static const std::unordered_map<std::string, int> ARGCOUNT = {
    {"read",3},    {"write",3},   {"open",3},    {"close",1},
    {"stat",2},    {"fstat",2},   {"lstat",2},   {"lseek",3},
    {"mmap",6},    {"mprotect",3},{"munmap",2},  {"brk",1},
    {"ioctl",3},   {"access",2},  {"dup",1},     {"dup2",2},
    {"fork",0},    {"vfork",0},   {"execve",3},  {"exit",1},
    {"exit_group",1}, {"wait4",4},{"kill",2},    {"getpid",0},
    {"getuid",0},  {"getgid",0},  {"getppid",0}, {"getcwd",2},
    {"chdir",1},   {"mkdir",2},   {"rmdir",1},   {"rename",2},
    {"unlink",1},  {"openat",4},  {"newfstatat",4},{"clone",5},
    {"futex",6},   {"nanosleep",2},{"socket",3}, {"connect",3},
    {"bind",3},    {"listen",2},  {"accept",3},  {"sendto",6},
    {"recvfrom",6},{"pipe",1},    {"pipe2",2},   {"fcntl",3},
    {"rt_sigaction",3}, {"rt_sigprocmask",3},
};

// ============================================================
//  Public helper — look up syscall name (returns empty string
//  fallback so callers can detect unknown numbers)
// ============================================================
const std::string& syscall_name(long nr) {
    static const std::string UNKNOWN = "";
    auto it = SYSCALL_NAMES.find(nr);
    return (it != SYSCALL_NAMES.end()) ? it->second : UNKNOWN;
}

// ============================================================
//  Public helper — look up errno symbol
// ============================================================
const std::string& errno_name(long err) {
    static const std::string UNKNOWN = "";
    auto it = ERRNO_NAMES.find(err);
    return (it != ERRNO_NAMES.end()) ? it->second : UNKNOWN;
}

// ============================================================
//  Public helper — look up arg count for a syscall name
// ============================================================
int syscall_argcount(const std::string& name) {
    auto it = ARGCOUNT.find(name);
    return (it != ARGCOUNT.end()) ? it->second : 3; // default 3
}

// ============================================================
//  read_tracee_string()
//
//  Safely reads a NUL-terminated C-string from the tracee's
//  virtual address space using PTRACE_PEEKDATA (one word at a
//  time).  Returns "NULL" for null pointers, and appends "..."
//  if the string is truncated at max_len bytes.
// ============================================================
std::string read_tracee_string(pid_t pid, unsigned long addr, size_t max_len) {
    if (addr == 0) return "NULL";

    std::string result;
    result.reserve(max_len);

    // PTRACE_PEEKDATA reads one long-sized word per call.
    union {
        long val;
        char bytes[sizeof(long)];
    } data;

    for (size_t i = 0; i < max_len; i += sizeof(long)) {
        errno = 0;
        data.val = ptrace(PTRACE_PEEKDATA, pid,
                          reinterpret_cast<void*>(addr + i), nullptr);
        if (errno != 0) break; // unreadable page — stop

        for (size_t j = 0; j < sizeof(long); ++j) {
            if (data.bytes[j] == '\0') goto done; // NUL terminator found
            result += data.bytes[j];
        }
    }
done:
    if (result.size() >= max_len) result += "...";
    return "\"" + result + "\"";
}

// ============================================================
//  format_arg()
//
//  Decodes raw register value `val` into a human-readable
//  string for argument position `arg_idx` of syscall `syscall_nr`.
//
//  Strategy:
//    • Path arguments → read the string from tracee memory
//    • Buffer pointer  → show as 0xADDR (don't dereference)
//    • File descriptor → annotate stdin/stdout/stderr
//    • Large numbers   → hex; small numbers → decimal
// ============================================================
std::string format_arg(pid_t pid, long syscall_nr, int arg_idx, long val) {
    const std::string& name = syscall_name(syscall_nr);

    // Syscalls whose first (or second for *at variants) arg is a path
    static const std::set<std::string> PATH_SYSCALLS = {
        "open",    "openat",    "stat",     "lstat",     "access",
        "creat",   "mkdir",     "rmdir",    "unlink",    "chmod",
        "chown",   "rename",    "link",     "symlink",   "readlink",
        "truncate","chdir",     "execve",   "faccessat", "newfstatat",
        "mkdirat", "unlinkat",  "readlinkat"
    };

    // For *at() variants the path is arg[1]; for others it is arg[0]
    static const std::set<std::string> AT_VARIANTS = {
        "openat", "newfstatat", "mkdirat", "unlinkat",
        "faccessat", "readlinkat"
    };

    bool is_path = PATH_SYSCALLS.count(name) &&
                   (AT_VARIANTS.count(name) ? (arg_idx == 1) : (arg_idx == 0));

    if (is_path && val != 0)
        return read_tracee_string(pid, static_cast<unsigned long>(val));

    // Buffer pointer for read/write — show hex address, not content
    if ((name == "write" || name == "read" ||
         name == "pread64" || name == "pwrite64") && arg_idx == 1) {
        std::ostringstream o;
        o << "0x" << std::hex << val;
        return o.str();
    }

    // File descriptor (arg[0] for fd-based calls)
    static const std::set<std::string> FD_FIRST = {
        "read","write","close","fstat","ioctl","lseek","fcntl",
        "flock","fsync","fdatasync","ftruncate","fchmod","fchown",
        "fchdir","dup","dup2","sendto","recvfrom"
    };
    if (FD_FIRST.count(name) && arg_idx == 0) {
        if (val == 0) return "0<stdin>";
        if (val == 1) return "1<stdout>";
        if (val == 2) return "2<stderr>";
        return std::to_string(val);
    }

    // Default: hex for pointer-sized values, decimal for small ones
    if (val > 4096 || val < -1) {
        std::ostringstream o;
        o << "0x" << std::hex << val;
        return o.str();
    }
    return std::to_string(val);
}

// ============================================================
//  format_errno()
//
//  Converts a negative syscall return value into the canonical
//  strace format: "-1 ENOENT" (or "-1 E22" for unknowns).
// ============================================================
std::string format_errno(long retval) {
    long err = -retval;
    const std::string& sym = errno_name(err);
    if (!sym.empty())
        return "-1 " + sym;
    return "-1 E" + std::to_string(err);
}
