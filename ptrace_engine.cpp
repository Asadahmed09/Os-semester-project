// ============================================================
//  ptrace_engine.cpp
//
//  Contributor : 24k-1013  Asad Ahmed  (Team Lead)
//  Responsible : Ptrace Logic, Process Management
//
//  What this file owns:
//    • trace_loop()    — the core ptrace event loop that
//        alternates between syscall-entry and syscall-exit
//        stops, measures elapsed time, and dispatches to
//        print_syscall() (implemented by Lucky)
//    • The loop correctly handles:
//        - real signals delivered to the child (pass-through)
//        - PTRACE_O_EXITKILL so the tracee dies if we do
//        - graceful Ctrl-C (g_running flag)
//
//  GitHub commit scope: ONLY edit this file for anything
//  related to ptrace calls, waitpid, signal delivery, or
//  the entry/exit state machine.
//
//  Note on the entry/exit state machine:
//    Linux stops the tracee TWICE per syscall when
//    PTRACE_O_TRACESYSGOOD is active:
//      1st stop  (entering == true)  → syscall is about to execute
//      2nd stop  (entering == false) → syscall has returned
//    orig_rax holds the syscall number on both stops.
//    rax on the 2nd stop holds the return value.
// ============================================================

#include "sys_trace.h"

// ============================================================
//  trace_loop()
//
//  Core ptrace event loop.  Called after:
//    (a) fork()  + PTRACE_TRACEME in the child, OR
//    (b) PTRACE_ATTACH to an existing PID
//
//  Parameters:
//    tracee_pid  — PID to trace
//    cmd_label   — human label printed in the header/summary
// ============================================================
void trace_loop(pid_t tracee_pid, const std::string& cmd_label) {
    int  status = 0;
    bool C      = g_cfg.use_color;

    // ----------------------------------------------------------
    //  Step 1 — Wait for the initial stop.
    //
    //  For a freshly exec'd child (PTRACE_TRACEME path):
    //    execvp() triggers a SIGTRAP that stops the child before
    //    the new program's first instruction.
    //
    //  For PTRACE_ATTACH:
    //    The kernel sends SIGSTOP to the target; waitpid reaps it.
    // ----------------------------------------------------------
    if (waitpid(tracee_pid, &status, 0) < 0) {
        perror("waitpid (initial stop)");
        return;
    }
    if (!WIFSTOPPED(status)) {
        std::cerr << "[SysTrace] Unexpected initial status: "
                  << status << "\n";
        return;
    }

    // ----------------------------------------------------------
    //  Step 2 — Configure ptrace options.
    //
    //  PTRACE_O_TRACESYSGOOD
    //    Sets bit 7 of the signal number on syscall stops, giving
    //    (SIGTRAP | 0x80).  This lets us distinguish syscall stops
    //    from ordinary SIGTRAP signals without ambiguity.
    //
    //  PTRACE_O_EXITKILL
    //    If the tracer (us) exits unexpectedly, the tracee is
    //    killed automatically — prevents orphaned zombie processes.
    // ----------------------------------------------------------
    if (ptrace(PTRACE_SETOPTIONS, tracee_pid, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {
        perror("ptrace SETOPTIONS");
        // Non-fatal: continue without the options
    }

    // ----------------------------------------------------------
    //  Step 3 — Print the trace header banner.
    // ----------------------------------------------------------
    if (!g_cfg.summary_only) {
        std::cout << (C ? Color::BOLD + Color::CYAN : "")
                  << "SysTrace v1.0  |  Tracing: " << cmd_label
                  << "  (PID " << tracee_pid << ")"
                  << (C ? Color::RESET : "") << "\n"
                  << std::string(67, '-') << "\n";
    }

    // ----------------------------------------------------------
    //  Step 4 — Entry/exit state machine.
    //
    //  We alternate between two states:
    //    entering = true  → next syscall-stop is an ENTRY stop
    //    entering = false → next syscall-stop is an EXIT  stop
    //
    //  On ENTRY we snapshot the registers and start the timer.
    //  On EXIT  we read the updated registers (containing rax =
    //  return value), compute elapsed time, and call print_syscall().
    // ----------------------------------------------------------
    bool    entering  = true;
    struct  user_regs_struct regs_enter;    // snapshot at entry
    std::chrono::high_resolution_clock::time_point t_entry;

    while (g_running) {

        // ---- Resume the tracee; stop at the next syscall boundary ----
        if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) < 0) {
            // ESRCH means the child already exited — normal termination
            if (errno != ESRCH)
                perror("ptrace PTRACE_SYSCALL");
            break;
        }

        // ---- Wait for the next event ----
        if (waitpid(tracee_pid, &status, 0) < 0) {
            if (errno != ECHILD)
                perror("waitpid");
            break;
        }

        // ---- Process exited or was killed — stop tracing ----
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;

        // ---- Ignore non-stop events (shouldn't happen with SYSCALL) ----
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);

        // ---- Distinguish syscall-stops from signal-delivery stops ----
        //
        //  With PTRACE_O_TRACESYSGOOD, syscall stops deliver
        //  (SIGTRAP | 0x80) = 0x85.  Any other signal is a real
        //  signal that we should pass through to the child.
        // ----
        bool is_syscall_stop = (sig == (SIGTRAP | 0x80));

        if (!is_syscall_stop) {
            // Pass the real signal to the child.
            // Exception: bare SIGTRAP (e.g. from a breakpoint or exec)
            // should NOT be forwarded — send 0 to suppress it.
            int deliver = (sig == SIGTRAP) ? 0 : sig;
            ptrace(PTRACE_SYSCALL, tracee_pid, 0, deliver);
            continue;
        }

        // ---- Read the CPU registers from the tracee ----
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) < 0) {
            // Tracee may have exited between waitpid and GETREGS
            if (errno == ESRCH) break;
            perror("ptrace GETREGS");
            continue;
        }

        // ---- State machine ----
        if (entering) {
            // ENTRY stop: snapshot registers and record timestamp
            regs_enter = regs;
            t_entry    = std::chrono::high_resolution_clock::now();
            entering   = false;
        } else {
            // EXIT stop: compute elapsed time and emit the trace line
            auto t_exit    = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::micro>(
                                 t_exit - t_entry).count();

            // regs_enter holds entry state (syscall nr, args)
            // regs      holds exit  state (return value in rax)
            print_syscall(tracee_pid, regs_enter, regs, elapsed);
            entering = true;
        }
    } // end while (g_running)

    // ----------------------------------------------------------
    //  Step 5 — Print the summary table if requested.
    // ----------------------------------------------------------
    if (g_cfg.show_summary) {
        print_summary(cmd_label);
    }
}
