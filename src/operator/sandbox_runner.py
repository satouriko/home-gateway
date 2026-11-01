#!/usr/bin/env python3
"""Keep DSH bash confined while dropping Web listener capabilities.

The SDK supplies a bwrap profile. Masks are applied after its mounts so shell
commands cannot read model credentials, chat storage or the privileged socket.
No unavailable-runner fallback is permitted.
"""
import os
import sys


def command(arguments):
    arguments = list(arguments)
    if '--' not in arguments or arguments[:3] != ['--ro-bind','/','/']:
        raise ValueError('sandbox runner requires the SDK bwrap profile')
    boundary = arguments.index('--')
    if boundary == len(arguments)-1:
        raise ValueError('sandbox command is missing')
    masks = []
    for path in ['/var/lib/dsh/state','/var/lib/dsh-login','/run/net-gateway-agent']:
        masks.extend(['--tmpfs',path])
    return ['/usr/bin/setpriv','--ambient-caps=-all','--inh-caps=-all',
            '/usr/bin/bwrap',*arguments[:boundary],*masks,*arguments[boundary:]]


if __name__ == '__main__':
    try:
        argv = command(sys.argv[1:])
        os.execv(argv[0], argv)
    except Exception:
        print('gateway-sandbox: confined runner unavailable', file=sys.stderr)
        raise SystemExit(125)
