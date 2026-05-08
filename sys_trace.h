// ============================================================
//  systrace.h  —  Shared types, globals, and declarations


#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <set>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <cstdlib>

// Linux / POSIX
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>   // struct user_regs_struct
#include <sys/stat.h>

// ============================================================
//  ANSI Color Codes
// ============================================================
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    const std::string BRED    = "\033[1;31m";
    const std::string BGREEN  = "\033[1;32m";
    const std::string BCYAN   = "\033[1;36m";
}

// ============================================================
//  Syscall statistics record
// ============================================================
struct SyscallStat {
    long   count       = 0;
    double total_us    = 0.0;
    long   error_count = 0;
};

// ============================================================
//  Global configuration  (populated by CLI parser)
// ============================================================
struct Config {
    bool        verbose      = false;   // -v
    bool        summary_only = false;   // -s
    bool        show_summary = true;    // -c (default on)
    bool        use_color    = true;    // disabled by -n
    std::string outfile;                // -o <file>
    std::set<std::string> filter_syscalls; // -e trace=...  (empty = all)
    pid_t       attach_pid   = -1;      // -p <PID>
};

// ============================================================
//  Shared globals  — defined in systrace_main.cpp
// ============================================================
extern Config                      g_cfg;
extern std::map<long, SyscallStat> g_stats;
extern long                        g_call_count;
extern std::ofstream               g_logfile;
extern bool                        g_running;


//  Forward declarations


// --- (syscall_table.cpp) ---
const std::string& syscall_name(long nr);
const std::string& errno_name(long err);
std::string        read_tracee_string(pid_t pid, unsigned long addr,
                                      size_t max_len = 128);
std::string        format_arg(pid_t pid, long syscall_nr,
                               int arg_idx, long val);
std::string        format_errno(long retval);
int                syscall_argcount(const std::string& name);

// --- (cli_metrics.cpp) ---
void   parse_args(int argc, char* argv[], int& opt_idx);
void   usage(const char* prog);
void   print_syscall(pid_t pid,
                     const struct user_regs_struct& regs_entry,
                     const struct user_regs_struct& regs_exit,
                     double elapsed_us);
void   print_summary(const std::string& cmd_label);

// ---  (ptrace_engine.cpp) ---
void   trace_loop(pid_t tracee_pid, const std::string& cmd_label);
