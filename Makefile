# ============================================================
# OS Semester Project: System Call Tracer
#
# 24k-1013  Asad Ahmed       -> ptrace_engine.cpp
# 24k-0791  Shahnawaz Khuwaja -> syscall_table.cpp
# 24k-0865  Lucky             -> cli_metrics.cpp
# (shared)                    -> sys_trace_main.cpp
# ============================================================

# Compiler and Flags
CXX      := g++
# Using C++11 for compatibility at FAST; change to c++17 if required by Sir Shoaib
CXXFLAGS := -std=c++11 -Wall -Wextra -O2 -g
TARGET   := systrace

# List of Source Files based on your screenshot
SRCS     := sys_trace_main.cpp ptrace_engine.cpp syscall_table.cpp cli_metrics.cpp
# This creates a list of .o files from the .cpp files
OBJS     := $(SRCS:.cpp=.o)

# Default target: Build the program
all: $(TARGET)
	@echo "Build successful: ./$(TARGET)"

# Link the object files to create the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Compile each .cpp file into an .o file
# It depends on the .cpp file AND your header file sys_trace.h
%.o: %.cpp sys_trace.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)

# Convenience command to run the tracer on 'ls'
run: all
	./$(TARGET) ls

.PHONY: all clean run