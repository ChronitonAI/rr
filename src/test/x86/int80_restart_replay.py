from util import *

# The SIGSEGV at the restarted syscall instruction, before its handler runs
send_gdb('c')
expect_gdb('SIGSEGV')
send_gdb('p $pc == syscall_insn')
expect_gdb(r'\$1 = 1\b')
# i386 restart_syscall is 0
send_gdb('p $eax')
expect_gdb(r'\$2 = 0\b')

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
