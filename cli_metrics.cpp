// ============================================================
//  cli_metrics.cpp
//
//  Contributor : 24k-0865  Lucky
//  Responsible : CLI Interface, Performance Metrics
//
//  What this file owns:
//    • parse_args()    — parse all command-line flags into g_cfg
//    • usage()         — print the help banner
//    • print_syscall() — format and emit one traced syscall line
//        (color-coded name, arguments, return value, timing)
//    • print_summary() — render the final statistics table
//        (syscall name, count, errors, total µs, avg µs, %)
//
// ============================================================

#include "sys_trace.h"

// ============================================================
//  usage()
//
//  Prints the full help banner to stdout.
//  Called when the user passes -h / --help or gives no args.
// ============================================================
void usage(const char* prog) {
    std::cout <<
R"(
SysTrace - Linux System Call Tracer  (Mini-strace)


Usage:
  )" << prog << R"( [OPTIONS] <command> [args...]
  )" << prog << R"( -p <PID>

Options:
  -o <file>           Write trace output to a log file
  -e trace=<list>     Trace only listed syscalls (comma-separated)
                      e.g.  -e trace=open,read,write
  -v                  Verbose mode: show all 6 register args + µs timing
  -s                  Summary only  (suppress per-call output)
  -c                  Show count/timing summary at end  (default: on)
  -n                  No color output  (useful for piping / log files)
  -p <PID>            Attach to a running process by PID
  -h / --help         Show this help message

Examples:
  )" << prog << R"( ls -la
  )" << prog << R"( -o trace.log cat /etc/hostname
  )" << prog << R"( -e trace=open,read,write,close ls
  )" << prog << R"( -v -o out.log ./myprogram
  )" << prog << R"( -p $(pgrep firefox)
  sudo )" << prog << R"( -p <PID>          # required if ptrace_scope != 0

)" ;
}

// ============================================================
//  parse_args()
//
//  Reads argv starting at index 1, fills in g_cfg, and sets
//  opt_idx to the index of the first non-option argument
//  (i.e., the command to execute).
//
//  Exits the process (exit 1) on malformed input.
// ============================================================
void parse_args(int argc, char* argv[], int& opt_idx) {
    opt_idx = 1;

    while (opt_idx < argc) {
        std::string arg = argv[opt_idx];

        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            exit(0);
        }
        else if (arg == "-v") {
            g_cfg.verbose = true;
            ++opt_idx;
        }
        else if (arg == "-s") {
            g_cfg.summary_only = true;
            ++opt_idx;
        }
        else if (arg == "-n") {
            g_cfg.use_color = false;
            ++opt_idx;
        }
        else if (arg == "-c") {
            g_cfg.show_summary = true;
            ++opt_idx;
        }
        else if (arg == "-o") {
            if (opt_idx + 1 >= argc) {
                std::cerr << "Error: -o requires a filename argument.\n";
                exit(1);
            }
            g_cfg.outfile = argv[++opt_idx];
            ++opt_idx;
        }
        else if (arg == "-p") {
            if (opt_idx + 1 >= argc) {
                std::cerr << "Error: -p requires a PID argument.\n";
                exit(1);
            }
            try {
                g_cfg.attach_pid = std::stoi(argv[++opt_idx]);
            } catch (...) {
                std::cerr << "Error: -p argument must be a numeric PID.\n";
                exit(1);
            }
            ++opt_idx;
        }
        // Accept both  "-e trace=open,read"  and  "-e open,read"
        else if (arg.substr(0, 9) == "-e trace=") {
            std::string list = arg.substr(9);
            std::string token;
            for (char c : list + ",") {
                if (c == ',') {
                    if (!token.empty()) g_cfg.filter_syscalls.insert(token);
                    token.clear();
                } else {
                    token += c;
                }
            }
            ++opt_idx;
        }
        else if (arg == "-e") {
            if (opt_idx + 1 >= argc) {
                std::cerr << "Error: -e requires a syscall list.\n";
                exit(1);
            }
            std::string list = argv[++opt_idx];
            // Strip optional "trace=" prefix
            if (list.size() > 6 && list.substr(0, 6) == "trace=")
                list = list.substr(6);
            std::string token;
            for (char c : list + ",") {
                if (c == ',') {
                    if (!token.empty()) g_cfg.filter_syscalls.insert(token);
                    token.clear();
                } else {
                    token += c;
                }
            }
            ++opt_idx;
        }
        else {
            // First non-option token → start of the command to trace
            break;
        }
    }
}

// ============================================================
//  print_syscall()
//
//  Formats one completed syscall event and writes it to stdout
//  (and optionally the log file).
//
//  Output format (color mode):
//    GREEN_name(BLUE_arg0, BLUE_arg1, ...) = CYAN_retval
//    RED_name(...)                          = BRED_-1 ENOENT
//  Plain (no-color):
//    name(arg0, arg1, ...) = retval
//
//  Timing suffix (verbose mode only):
//    name(...) = retval  <12.345µs>
//
//  Also updates g_stats / g_call_count for the summary table.
// ============================================================
void print_syscall(pid_t pid,
                   const struct user_regs_struct& regs_entry,
                   const struct user_regs_struct& regs_exit,
                   double elapsed_us)
{
    long nr     = static_cast<long>(regs_entry.orig_rax);
    long retval = static_cast<long>(regs_exit.rax);

    // Resolve human-readable name (falls back to "syscall_NNN")
    const std::string& raw_name = syscall_name(nr);
    std::string name = raw_name.empty()
                       ? ("syscall_" + std::to_string(nr))
                       : raw_name;

    // ---- Apply syscall filter ----
    if (!g_cfg.filter_syscalls.empty() &&
        !g_cfg.filter_syscalls.count(name)) {
        return;
    }

    // ---- Update statistics ----
    g_stats[nr].count++;
    g_stats[nr].total_us += elapsed_us;
    if (retval < 0) g_stats[nr].error_count++;
    g_call_count++;

    if (g_cfg.summary_only) return; // accumulate stats but no output

    // ---- Build the output line ----
    bool C = g_cfg.use_color;

    // How many arguments to show
    int nargs = g_cfg.verbose ? 6 : syscall_argcount(name);

    // Raw argument registers (x86_64 Linux calling convention)
    long args[6] = {
        static_cast<long>(regs_entry.rdi),
        static_cast<long>(regs_entry.rsi),
        static_cast<long>(regs_entry.rdx),
        static_cast<long>(regs_entry.r10),
        static_cast<long>(regs_entry.r8),
        static_cast<long>(regs_entry.r9)
    };

    std::ostringstream line;

    // Syscall name — green on success, red on error
    if (C) {
        line << (retval < 0 ? Color::RED : Color::BGREEN)
             << name << Color::RESET;
    } else {
        line << name;
    }

    // Argument list
    line << "(";
    for (int i = 0; i < nargs; ++i) {
        if (i > 0) line << ", ";
        std::string arg_str = format_arg(pid, nr, i, args[i]);
        if (C) line << Color::BLUE << arg_str << Color::RESET;
        else   line << arg_str;
    }
    line << ") = ";

    // Return value
    if (retval < 0) {
        std::string err_str = format_errno(retval);
        if (C) line << Color::BRED << err_str << Color::RESET;
        else   line << err_str;
    } else {
        if (C) line << Color::CYAN << retval << Color::RESET;
        else   line << retval;
    }

    // Optional timing annotation
    if (g_cfg.verbose) {
        line << "  <"
             << std::fixed << std::setprecision(3)
             << elapsed_us << "\xc2\xb5s>"; // µs in UTF-8
    }

    std::string out = line.str();
    std::cout << out << "\n";

    // ---- Write clean (ANSI-stripped) copy to log file ----
    if (g_logfile.is_open()) {
        std::string clean;
        clean.reserve(out.size());
        bool in_escape = false;
        for (unsigned char c : out) {
            if (c == '\033') { in_escape = true; continue; }
            if (in_escape)   { if (c == 'm') in_escape = false; continue; }
            clean += static_cast<char>(c);
        }
        g_logfile << clean << "\n";
    }
}

// ============================================================
//  print_summary()
//
//  Renders the final per-syscall statistics table, sorted by
//  call count descending.
//
//  Columns: Syscall | Count | Errors | Total µs | Avg µs | %
//
//  Rows with errors are highlighted yellow (color mode).
// ============================================================
void print_summary(const std::string& cmd_label) {
    if (g_stats.empty()) return;

    // Sort by call count, highest first
    std::vector<std::pair<long, SyscallStat>> sorted(
        g_stats.begin(), g_stats.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const std::pair<long, SyscallStat>& a,
                 const std::pair<long, SyscallStat>& b) {
                  return a.second.count > b.second.count;
              });

    bool C = g_cfg.use_color;

    // Header
    std::cout << "\n"
              << (C ? Color::BOLD : "")
              << "=================================================================\n"
              << "  SysTrace Summary  |  " << cmd_label << "\n"
              << "  Total syscalls tracked: " << g_call_count << "\n"
              << "=================================================================\n"
              << (C ? Color::RESET : "");

    // Column headers
    std::cout << (C ? Color::BCYAN : "")
              << std::left  << std::setw(22) << "Syscall"
              << std::right << std::setw(8)  << "Count"
              << std::right << std::setw(8)  << "Errors"
              << std::right << std::setw(12) << "Total µs"
              << std::right << std::setw(10) << "Avg µs"
              << std::right << std::setw(7)  << "%"
              << (C ? Color::RESET : "") << "\n"
              << std::string(67, '-') << "\n";

    // Data rows
    for (const auto& entry : sorted) {
        long nr          = entry.first;
        const SyscallStat& st = entry.second;

        const std::string& raw_nm = syscall_name(nr);
        std::string nm = raw_nm.empty()
                         ? ("syscall_" + std::to_string(nr))
                         : raw_nm;

        double pct = g_call_count
                     ? (100.0 * static_cast<double>(st.count) /
                        static_cast<double>(g_call_count))
                     : 0.0;
        double avg = st.count
                     ? (st.total_us / static_cast<double>(st.count))
                     : 0.0;

        // Yellow for rows that had any errors
        if (C && st.error_count > 0) std::cout << Color::YELLOW;

        std::cout
            << std::left  << std::setw(22) << nm
            << std::right << std::setw(8)  << st.count
            << std::right << std::setw(8)  << st.error_count
            << std::right << std::setw(12) << std::fixed
                          << std::setprecision(1) << st.total_us
            << std::right << std::setw(10) << std::fixed
                          << std::setprecision(2) << avg
            << std::right << std::setw(6)  << std::fixed
                          << std::setprecision(1) << pct << "%";

        if (C && st.error_count > 0) std::cout << Color::RESET;
        std::cout << "\n";
    }

    std::cout << std::string(67, '=') << "\n\n";

    // Also write summary to log file if open
    if (g_logfile.is_open()) {
        g_logfile << "\n[Summary] Total syscalls: " << g_call_count
                  << "  |  " << cmd_label << "\n";
        for (const auto& entry : sorted) {
            long nr = entry.first;
            const SyscallStat& st = entry.second;
            const std::string& raw_nm = syscall_name(nr);
            std::string nm = raw_nm.empty()
                             ? ("syscall_" + std::to_string(nr))
                             : raw_nm;
            double avg = st.count ? (st.total_us / st.count) : 0.0;
            g_logfile << "  " << std::left << std::setw(22) << nm
                      << "  count=" << st.count
                      << "  errors=" << st.error_count
                      << "  avg_us=" << std::fixed
                      << std::setprecision(2) << avg << "\n";
        }
    }
}
