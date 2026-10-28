#!/usr/bin/env python3
"""Linux controller. Run --help on Windows; kernel commands require Linux/root."""
import argparse
import contextlib
import csv
import ctypes
import ctypes.util
import json
import math
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
PIN = Path('/sys/fs/bpf/kavach')
RUN = Path('/run/kavach')
STATE = RUN / 'state.json'
NAMES = ('seen', 'pass_non_ipv4', 'pass_non_udp', 'pass_non53',
         'pass_fragment', 'pass_truncated', 'pass_invalid_ipv4', 'dns_pass',
         'drop_bad_udp', 'drop_short_dns', 'drop_src', 'drop_global',
         'drop_busy', 'drop_state')
MAPS = {'counters': ('percpu_array', 4, 8, 14),
        'kavach_cfg': ('array', 4, 40, 1),
        'src_tat': ('lru_hash', 4, 8, 100000),
        'global_tat': ('array', 4, 8, 1)}
MODES = {'generic': 2, 'native': 4}

def command(args, diagnostics=False):
    result = subprocess.run(args, capture_output=True, text=True)
    if diagnostics and result.stderr:
        print(result.stderr, end='', file=sys.stderr)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout

def bpf(*args):
    return json.loads(command(['bpftool', '-j', *map(str, args)]))

def one(value):
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError('Expected one BPF object')
        return value[0]
    return value

def number(value):
    if isinstance(value, bool):
        raise ValueError('Unexpected boolean')
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int.from_bytes(bytes(number(x) for x in value), sys.byteorder)

def pack_config(sr, sb, gr, gb):
    fields, flags = [], 0
    for rate, burst, flag in ((sr, sb, 1), (gr, gb, 2)):
        if not 0 <= rate <= 1_000_000_000:
            raise ValueError('Rate must be 0..1,000,000,000 packets/s')
        if not 1 <= burst <= 1_000_000:
            raise ValueError('Burst must be 1..1,000,000 packets')
        interval = (1_000_000_000 + rate - 1) // rate if rate else 0
        tolerance = (burst - 1) * interval
        if tolerance > 3_600_000_000_000:
            raise ValueError('Burst tolerance must not exceed one hour')
        fields.extend((interval, tolerance))
        flags |= flag if rate else 0
    # Native endian, standard field widths; matches the kernel's struct layout.
    return struct.pack('=QQQQII', *fields, flags, 0)

def snapshot():
    entries = bpf('map', 'dump', 'pinned', PIN / 'counters')
    totals = {}
    for entry in entries:
        item = entry.get('formatted', entry)
        key = number(item['key'])
        if not 0 <= key < len(NAMES):
            raise RuntimeError('Counter layout differs from this controller')
        totals[NAMES[key]] = sum(number(v['value']) for v in item['values'])
    if set(totals) != set(NAMES):
        raise RuntimeError('Missing counters')
    return totals

def program():
    info = one(bpf('prog', 'show', 'pinned', PIN / 'prog'))
    if info.get('type') != 'xdp' or info.get('name') != 'kavach_xdp':
        raise RuntimeError('Pin does not contain the expected Kavach program')
    return info

def check_maps():
    info = program()
    for name, (kind, key, value, maximum) in MAPS.items():
        m = one(bpf('map', 'show', 'pinned', PIN / name))
        actual = (m.get('type'), m.get('bytes_key'), m.get('bytes_value'), m.get('max_entries'))
        if actual != (kind, key, value, maximum):
            raise RuntimeError(f'Map {name} has incompatible layout: {actual}')
        if m['id'] not in info.get('map_ids', []):
            raise RuntimeError(f'Map {name} is not used by the pinned program; unload the old parser first')
    return info

class AttachOptions(ctypes.Structure):
    _fields_ = [('sz', ctypes.c_size_t), ('old_prog_fd', ctypes.c_int)]

class XDP:
    """libbpf attach/detach; expected old FD makes detachment conditional in-kernel."""
    def __init__(self):
        name = ctypes.util.find_library('bpf')
        if not name:
            raise RuntimeError('libbpf shared library missing; install libbpf-dev')
        self.lib = ctypes.CDLL(name, use_errno=True)
        signatures = {
            'bpf_obj_get': ([ctypes.c_char_p], ctypes.c_int),
            'bpf_prog_get_fd_by_id': ([ctypes.c_uint32], ctypes.c_int),
            'bpf_xdp_query_id': ([ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)], ctypes.c_int),
            'bpf_xdp_attach': ([ctypes.c_int, ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(AttachOptions)], ctypes.c_int),
            'bpf_xdp_detach': ([ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(AttachOptions)], ctypes.c_int),
        }
        for function, (args, result) in signatures.items():
            func = getattr(self.lib, function)
            func.argtypes, func.restype = args, result

    def fd(self, prog_id):
        fd = self.lib.bpf_prog_get_fd_by_id(prog_id)
        if fd < 0:
            raise RuntimeError(f'Cannot open program {prog_id}: {os.strerror(ctypes.get_errno() or -fd)}')
        return fd

    def query(self, index, flags):
        value = ctypes.c_uint32()
        result = self.lib.bpf_xdp_query_id(index, flags, ctypes.byref(value))
        if result:
            raise RuntimeError(f'Cannot query XDP on ifindex {index}: {os.strerror(-result)}')
        return value.value

    def attach(self, index, fd, mode):
        # UPDATE_IF_NOEXIST: never overwrite an existing program in this mode.
        result = self.lib.bpf_xdp_attach(index, fd, MODES[mode] | 1, None)
        if result:
            raise RuntimeError(f'XDP {mode} attach failed: {os.strerror(-result)}')

    def detach(self, index, fd, mode):
        opts = AttachOptions(ctypes.sizeof(AttachOptions), fd)
        result = self.lib.bpf_xdp_detach(index, MODES[mode], ctypes.byref(opts))
        if result:
            raise RuntimeError(f'Conditional XDP detach failed: {os.strerror(-result)}')

def attachments(xdp, prog_id=None):
    found = []
    for index, iface in socket.if_nameindex():
        for mode, flag in MODES.items():
            value = xdp.query(index, flag)
            if value and (prog_id is None or value == prog_id):
                found.append({'iface': iface, 'ifindex': index, 'mode': mode, 'prog_id': value})
    return found

def guard(iface):
    if iface == 'lo':
        raise RuntimeError('Use a veth or dedicated test NIC, not loopback')
    for family in ('-4', '-6'):
        routes = json.loads(command(['ip', '-j', family, 'route', 'show', 'table', 'all']))
        for route in routes:
            if route.get('dst') not in ('default', '0.0.0.0/0', '::/0'):
                continue
            devices = {route.get('dev')} | {hop.get('dev') for hop in route.get('nexthops', [])}
            if iface in devices:
                raise RuntimeError(f'{iface} carries a default route; use the isolated test NIC')
    return socket.if_nametoindex(iface)

def read_state():
    try:
        return json.loads(STATE.read_text())
    except FileNotFoundError:
        return None

def write_state(value):
    temp = STATE.with_suffix('.tmp')
    temp.write_text(json.dumps(value))
    temp.chmod(0o600)
    os.replace(temp, STATE)

def clear_state():
    STATE.unlink(missing_ok=True)

@contextlib.contextmanager
def locked():
    import fcntl
    RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (RUN / 'control.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield

def cmd_load(args):
    obj = args.obj.resolve()
    if not obj.is_file():
        raise RuntimeError(f'Build first: make -C {HERE}')
    if '_approx' in obj.stem and not getattr(args, 'allow_approximate', False):
        raise RuntimeError('Approximate build requires --allow-approximate and a documented lab decision')
    with locked():
        if PIN.exists():
            raise RuntimeError('Pin directory already exists. Inspect status, detach, then unload before loading fresh state.')
        if not os.path.ismount('/sys/fs/bpf'):
            raise RuntimeError('Mount bpffs at /sys/fs/bpf first')
        PIN.mkdir()
        try:
            # Load only; diagnostics remain on stderr via the command wrapper.
            command(['bpftool', '-d', 'prog', 'load', str(obj), str(PIN / 'prog'),
                     'type', 'xdp', 'pinmaps', str(PIN)], diagnostics=True)
            info = check_maps()
        except Exception:
            # This invocation created this directory; remove only its direct pins.
            for child in PIN.iterdir():
                if child.is_file():
                    child.unlink()
            PIN.rmdir()
            raise
    print(f"Loaded program {info['id']}; detached; limiters disabled.", file=sys.stderr)

def cmd_config(args):
    value = pack_config(args.src_rate, args.src_burst, args.glob_rate, args.glob_burst)
    with locked():
        info = check_maps()
        if attachments(XDP(), info['id']):
            raise RuntimeError('Detach before changing config; stop any concurrent prog-run tests too')
        command(['bpftool', 'map', 'update', 'pinned', str(PIN / 'kavach_cfg'),
                 'key', 'hex', '00', '00', '00', '00', 'value', 'hex',
                 *[f'{byte:02x}' for byte in value]])
    print('Config written. Reload before an independent test to reset limiter state.', file=sys.stderr)

def cmd_attach(args):
    if not math.isfinite(args.watchdog_minutes) or not 0 < args.watchdog_minutes <= 1440:
        raise ValueError('watchdog-minutes must be > 0 and <= 1440')
    with locked():
        index = guard(args.iface)
        info = check_maps()
        xdp = XDP()
        if attachments(xdp, info['id']):
            raise RuntimeError('This program is already attached; detach first')
        if any(xdp.query(index, flag) for flag in (2, 4, 8)):
            raise RuntimeError('Interface already has XDP; it will not be overwritten')
        state = {'token': uuid.uuid4().hex, 'iface': args.iface, 'ifindex': index,
                 'mode': args.mode, 'prog_id': info['id'],
                 'deadline': time.monotonic() + args.watchdog_minutes * 60}
        write_state(state)
        fd = xdp.fd(info['id'])
        attached = False
        readfd, writefd = os.pipe()
        try:
            with (RUN / 'watchdog.log').open('a') as log:
                child = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), '_watchdog',
                     '--token', state['token'], '--ready-fd', str(writefd)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    start_new_session=True, pass_fds=(writefd,))
            os.close(writefd)
            writefd = -1
            if not select.select([readfd], [], [], 10)[0] or os.read(readfd, 1) != b'R':
                raise RuntimeError('Watchdog did not become ready; see /run/kavach/watchdog.log')
            if child.poll() is not None:
                raise RuntimeError('Watchdog exited before attachment')
            state['watchdog_pid'] = child.pid
            write_state(state)
            xdp.attach(index, fd, args.mode)
            attached = True
            if xdp.query(index, MODES[args.mode]) != info['id']:
                raise RuntimeError('Attachment verification failed')
        except Exception:
            clear_state()
            if attached:
                xdp.detach(index, fd, args.mode)
            raise
        finally:
            os.close(fd)
            os.close(readfd)
            if writefd >= 0:
                os.close(writefd)
    print(f'Attached {args.mode} to {args.iface}; watchdog expires in {args.watchdog_minutes:g} minutes.', file=sys.stderr)

def cmd_watchdog(args):
    state = read_state()
    if not state or state['token'] != args.token:
        return
    xdp = XDP()
    fd = xdp.fd(state['prog_id'])
    try:
        os.write(args.ready_fd, b'R')
        os.close(args.ready_fd)
        while True:
            current = read_state()
            if not current or current['token'] != args.token:
                return
            remaining = state['deadline'] - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1, remaining))
        with locked():
            current = read_state()
            if not current or current['token'] != args.token:
                return
            # Verify interface identity, then use expected FD for atomic ownership check.
            if socket.if_nametoindex(state['iface']) == state['ifindex']:
                if xdp.query(state['ifindex'], MODES[state['mode']]) == state['prog_id']:
                    xdp.detach(state['ifindex'], fd, state['mode'])
                    print(f"Watchdog detached {state['iface']} ({state['mode']}); counters retained.", flush=True)
            clear_state()
    finally:
        os.close(fd)

def cmd_detach(args):
    with locked():
        info = program()
        index = socket.if_nametoindex(args.iface)
        xdp = XDP()
        matches = [mode for mode, flag in MODES.items() if xdp.query(index, flag) == info['id']]
        fd = xdp.fd(info['id'])
        try:
            for mode in matches:
                xdp.detach(index, fd, mode)
        finally:
            os.close(fd)
        state = read_state()
        if state and state['iface'] == args.iface:
            clear_state()
    print('Owned program detached (or already detached); pins and counters retained.', file=sys.stderr)

def cmd_unload(args):
    with locked():
        if not PIN.exists():
            print('Already unloaded.', file=sys.stderr)
            return
        if (PIN / 'prog').exists():
            info = program()
            if attachments(XDP(), info['id']):
                raise RuntimeError('Detach the owned program before unload')
        allowed = {'prog', *MAPS}
        entries = list(PIN.iterdir())
        if any(p.name not in allowed for p in entries):
            raise RuntimeError('Unexpected pin in Kavach directory; inspect manually')
        for path in entries:
            if path.name != 'prog':
                m = one(bpf('map', 'show', 'pinned', path))
                if m.get('name') != path.name:
                    raise RuntimeError('Unexpected pinned map identity')
        for path in entries:
            path.unlink()
        PIN.rmdir()
        clear_state()
    print('Unloaded; fresh load will reset all counters and TAT state.', file=sys.stderr)

def cmd_stats(args):
    if args.interval <= 0 or not math.isfinite(args.interval) or args.count < 0:
        raise ValueError('interval must be positive; count must be >= 0')
    info = check_maps()
    writer = csv.writer(sys.stdout) if args.csv else None
    if writer:
        writer.writerow(('timestamp_ns', *NAMES))
    iteration, deadline = 0, time.monotonic()
    while True:
        if program()['id'] != info['id']:
            raise RuntimeError('Program changed during stats sampling')
        counters = snapshot()
        timestamp = time.time_ns()
        if writer:
            writer.writerow((timestamp, *[counters[name] for name in NAMES]))
        else:
            print(json.dumps({'timestamp_ns': timestamp, **counters}))
        sys.stdout.flush()
        iteration += 1
        if args.once or (args.count and iteration >= args.count):
            break
        deadline += args.interval
        time.sleep(max(0, deadline - time.monotonic()))

def cmd_status(args):
    info = program() if (PIN / 'prog').exists() else None
    print(json.dumps({'program': info, 'attachments': attachments(XDP(), info['id']) if info else [],
                      'watchdog': read_state()}, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('load'); p.add_argument('--obj', type=Path, default=HERE / 'kavach_xdp.o')
    p.add_argument('--allow-approximate', action='store_true'); p.set_defaults(fn=cmd_load)
    p = sub.add_parser('attach'); p.add_argument('mode', choices=MODES); p.add_argument('--iface', required=True)
    p.add_argument('--watchdog-minutes', type=float, default=5); p.set_defaults(fn=cmd_attach)
    p = sub.add_parser('config')
    for name, default in (('src-rate', 0), ('src-burst', 1), ('glob-rate', 0), ('glob-burst', 1)):
        p.add_argument('--' + name, type=int, default=default)
    p.set_defaults(fn=cmd_config)
    p = sub.add_parser('stats'); p.add_argument('--csv', action='store_true'); p.add_argument('--once', action='store_true')
    p.add_argument('--interval', type=float, default=1); p.add_argument('--count', type=int, default=0); p.set_defaults(fn=cmd_stats)
    p = sub.add_parser('detach'); p.add_argument('--iface', required=True); p.set_defaults(fn=cmd_detach)
    sub.add_parser('unload').set_defaults(fn=cmd_unload)
    sub.add_parser('status').set_defaults(fn=cmd_status)
    p = sub.add_parser('_watchdog'); p.add_argument('--token', required=True); p.add_argument('--ready-fd', type=int, required=True); p.set_defaults(fn=cmd_watchdog)
    args = parser.parse_args()
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('Kernel commands require Linux and sudo; Windows is for editing and Git push')
    args.fn(args)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
