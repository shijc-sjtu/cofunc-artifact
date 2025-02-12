# Establish gdb connection through the port specified in build/gdb-port.
# Provide two commands: add-symbol-file-off and prepare-load-lib.
source ./scripts/gdb/gdb.py

set substitute-path /chos/ ./
add-symbol-file-off build/chcore-libc/lib/libc.so 0x400000000000
add-symbol-file-off build/kernel.img
