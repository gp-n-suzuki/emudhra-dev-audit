"""Harmless controls for one macOS sandbox profile; prints no fixture content."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import sys


root = Path(sys.argv[1])
allowed_port, other_port = int(sys.argv[2]), int(sys.argv[3])
work = root / 'work'
result = {}


def operation(name, func):
    try:
        func()
        result[name] = 'allowed'
    except OSError as exc:
        result[name] = 'denied' if exc.errno in (errno.EPERM, errno.EACCES) else 'error'


operation('file_read', lambda: (root / 'blocked' / 'data').read_bytes())
operation('alias_read', lambda: (work / 'alias').read_bytes())


def hardlink():
    target = work / 'hardlink'
    os.link(root / 'blocked' / 'data', target)
    target.unlink()


operation('hardlink', hardlink)
operation('outside_write', lambda: (root / 'outside' / 'out').write_text('synthetic'))
operation('alias_write', lambda: (work / 'write-alias').write_text('synthetic'))
operation('scratch_write', lambda: (work / 'scratch').write_text('synthetic'))


def unix_socket():
    target = str(work / 'test.sock')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(target)
    os.unlink(target)


operation('unix_socket', unix_socket)


def connect(host, port):
    with socket.create_connection((host, port), timeout=2):
        pass


operation('allowed_port', lambda: connect('127.0.0.1', allowed_port))
operation('other_port', lambda: connect('127.0.0.1', other_port))
operation('other_loopback', lambda: connect('127.0.0.2', allowed_port))
try:
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    bootstrap = ctypes.c_uint.in_dll(lib, 'bootstrap_port').value
    port = ctypes.c_uint()
    lib.bootstrap_look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
    lib.bootstrap_look_up.restype = ctypes.c_int
    result['mach_lookup'] = lib.bootstrap_look_up(bootstrap, b'com.apple.system.logger', ctypes.byref(port))
    if result['mach_lookup'] == 0:
        lib.mach_port_deallocate(lib.mach_task_self(), port.value)
except (AttributeError, OSError, ValueError):
    result['mach_lookup'] = 'error'
print(json.dumps(result, sort_keys=True))
