#!/bin/sh
python exploit.py --gdbplugin gef --host 127.0.0.1 --port 1024 --ld ld-linux-x86-64.so.2 --libc libc-2.29.so --pre-load-libc --exec attach 0xe664b
