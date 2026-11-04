"""Keep a probe's process-group leader alive until the controller cleans it up.

The only output from this helper is the child exit code on the supplied pipe.
All diagnostic input/output belongs to the child and is not interpreted here.
"""
import os
import signal
import subprocess
import sys


def main():
    status_fd = int(sys.argv[1])
    try:
        child = subprocess.Popen(sys.argv[2:], close_fds=True)
    except OSError:
        child = None
    # The controller sees EOF as soon as the child and its descendants
    # close these descriptors, not when this group anchor is terminated.
    for fd in (0, 1, 2):
        try:
            os.close(fd)
        except OSError:
            pass
    code = child.wait() if child is not None else 127
    os.write(status_fd, (str(code)+'\n').encode('ascii'))
    os.close(status_fd)
    while True:
        signal.pause()


if __name__ == '__main__':
    main()
