from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

# Check the unwinding from the syscall hook. (When the syscallbuf can't
# handle the syscall, it unwinds and the syscall is performed in the extended
# jump patch.)
send_gdb('break syscall_hook')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('where')
expect_gdb(' main ')

ok()
