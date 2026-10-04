from util import *

# We're at the exit of the interrupted nanosleep(), after the syscall
# instruction, so continuing doesn't step over this breakpoint: it's in
# memory when replay restarts the syscall, and we stop there.
send_gdb('break *syscall_insn')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1,')
send_gdb('p $pc == syscall_insn')
expect_gdb(r'\$1 = 1\b')
# i386 restart_syscall is 0
send_gdb('p $eax')
expect_gdb(r'\$2 = 0\b')

send_gdb('delete 1')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
