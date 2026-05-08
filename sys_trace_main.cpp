
//
//  This file:
//    • Defines all shared globals (extern in systrace.h)
//    • Implements main()
// ============================================================

#include "sys_trace.h"

// ============================================================
//  Shared global definitions
//  (declared as extern in systrace.h — all modules see them)
// ============================================================
Config                      g_cfg;          // CLI config 
std::map<long, SyscallStat> g_stats;        // per-syscall stats
long                        g_call_count = 0;
std::ofstream               g_logfile;      // optional output file
bool                        g_running    = true;

// ============================================================
//  SIGINT handler  — lets Ctrl-C print the summary gracefully
//  instead of hard-killing the program mid-trace.
// ============================================================
static void sigint_handler(int /*sig*/) {
    g_running = false;
}

// ============================================================
//  main()
// ============================================================
int main(int argc, char* argv[]) {

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // ---- Parse CLI flags 
    int opt_idx = 1;
    parse_args(argc, argv, opt_idx);

    // ---- Open log file if requested ----
    if (!g_cfg.outfile.empty()) {
        g_logfile.open(g_cfg.outfile);
        if (!g_logfile) {
            std::cerr << "Error: Cannot open output file: "
                      << g_cfg.outfile << "\n";
            return 1;
        }
    }

    // ---- Register Ctrl-C handler ----
    signal(SIGINT, sigint_handler);

    // ============================================================
    //  Mode A — Attach to an existing process  (-p <PID>)
    // ============================================================
    if (g_cfg.attach_pid > 0) {
        pid_t pid = g_cfg.attach_pid;

        if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
            std::cerr << "Error: PTRACE_ATTACH failed for PID " << pid
                      << ": " << strerror(errno) << "\n"
                      << "Hint: run as root, or:\n"
                      << "  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n";
            return 1;
        }

        std::cout << "[SysTrace] Attached to PID " << pid << "\n";
        trace_loop(pid, "PID:" + std::to_string(pid));  
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 0;
    }

    // ============================================================
    //  Mode B — Spawn a new child process and trace it
    // ============================================================
    if (opt_idx >= argc) {
        std::cerr << "Error: No command specified.\n";
        usage(argv[0]);
        return 1;
    }

    std::string cmd_label = argv[opt_idx]; // first word of the command

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        // ---- Child process ----
        // Tell the kernel we want to be traced.
        // The next exec will trigger a SIGTRAP, stopping us
        // before the new program's first instruction.
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("PTRACE_TRACEME");
            exit(1);
        }
        execvp(argv[opt_idx], argv + opt_idx);
        // execvp only returns on error
        std::cerr << "Error: execvp \"" << argv[opt_idx]
                  << "\": " << strerror(errno) << "\n";
        exit(1);
    }

    
    trace_loop(child, cmd_label);

    return 0;
}
