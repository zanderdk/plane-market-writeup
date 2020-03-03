from pwn import *
from struct import pack
import argparse
from typing import Union

#settings
systemLd = '/usr/lib/ld-linux-x86-64.so.2'
systemLibc = '/usr/lib/libc.so.6'
pwndbgSettings = '''
set context-code-lines 8
set context-stack-lines 4
set context-sections 'regs disasm code stack'
'''
gefSettings = '''
gef config context.layout "legend regs code args source memory stack"
gef config context.nb_lines_code 8
gef config context.nb_lines_stack 4
'''

def u64Var(addr: bytes):
    return u64(addr + b'\x00' * ( 8 - len(addr) ))

def u32Var(addr: bytes):
    return u32(addr + b'\x00' * ( 4 - len(addr) ))

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

parser = argparse.ArgumentParser(description='pwn script for CTF. You can also use the pwntools arguments such as NOASLR')
parser.add_argument('--gdbplugin', dest='gdbplugin', default='gef',
                    help='chose gdb init script gef pwndbg or path (default: gef)')
parser.add_argument('--libc', dest='libc', default=systemLibc,
                    help='libc path (defaults: system libc 64bit). For gef heap stuff to work name cannot be libc.so.6')
parser.add_argument('--ld', dest='ld', default=systemLd,
                    help='ld path (defaults: system ld 64bit)')
parser.add_argument('--exec', dest='exec', default='attach',
                    help='how to execute debug/local/remote/attach')
parser.add_argument('--host', dest='host', default='None',
                    help='ip of remote host')
parser.add_argument('--port', dest='port', default=None,
                    help='port of remote host')
parser.add_argument("--solid-events", dest='events', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="break on solid events such as lib loading")
parser.add_argument("--pre-load-ld", dest='preloadld', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="if true preload the specified ld")
parser.add_argument("--pre-load-libc", dest='preloadlibc', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="if true preload the specified libc")                        
parser.add_argument('onegadget', metavar='N', nargs='*',
                    help='onegadget to try')

args = parser.parse_args()

def setup(elfPath: str, breakpoints: str):
    gdbSettings = '''
    set breakpoint pending on
    '''

    if args.gdbplugin == 'gef':
        args.gdbplugin = './gefinit'
        gdbSettings += gefSettings

    if args.gdbplugin == 'pwndbg':
        args.gdbplugin = './pwndbginit'
        gdbSettings += pwndbgSettings

    if args.events:
        gdbSettings += 'set stop-on-solib-events 1'

    args.ld = os.path.abspath(args.ld)
    args.libc = os.path.abspath(args.libc)
    preloadString = ''
    if args.preloadld:
        preloadString = args.ld     
    
    if args.preloadlibc:
        if preloadString != '':
            preloadString += ' '
        preloadString += args.libc

    env = my_env = os.environ.copy()
    env["LD_PRELOAD"] = preloadString

    context.clear(terminal=['gnome-terminal', '-e'], gdbinit=args.gdbplugin, binary = ELF(elfPath))
    elf = context.binary

    gdbSettings += breakpoints

    if args.exec == 'attach':
        if preloadString == '':
            io = process(elf.path)
        else:
            io = process(elf.path, env=env)
        pwnlib.gdb.attach(io, gdbSettings)
    if args.exec == 'debug':
        if preloadString != '':
            io = pwnlib.gdb.debug(elf.path, gdbSettings, env=env)
        else:
            io = pwnlib.gdb.debug(elf.path, gdbSettings)
    if args.exec == 'local':
        if preloadString == '':
            io = process(elf.path)
        else:
            io = process(elf.path, env=env)
    if args.exec == 'remote':
        io = remote(args.host, args.port)

    libc = ELF(args.libc)
    ld = ELF(args.ld)

    if args.onegadget:
        onegadget = args.onegadget[0]
        onegadget = int(args.onegadget[0], 16) if onegadget[0:2] == '0x' else int(onegadget)
        return io, elf, libc, ld, onegadget
    return io, elf, libc, ld, None