"""Host-only controller unit tests. No root privileges or network changes."""
import contextlib
import ctypes
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('kavach_ctl', Path(__file__).resolve().parents[1] / 'kavach_ctl.py')
ctl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctl)

class ControllerTests(unittest.TestCase):
    def test_config_layout_and_rounding(self):
        self.assertEqual(struct.unpack('=QQQQII', ctl.pack_config(50,5,0,1)), (20000000,80000000,0,0,1,0))
        self.assertEqual(struct.unpack('=QQQQII', ctl.pack_config(3,2,7,3)), (333333334,333333334,142857143,285714286,3,0))
        self.assertEqual(len(ctl.pack_config(0,1,0,1)),40)

    def test_invalid_config(self):
        for values in ((-1,1,0,1),(1000000001,1,0,1),(1,0,0,1),(1,1000001,0,1),(1,10000,0,1)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ctl.pack_config(*values)

    def test_counter_formats(self):
        for formatted in (False,True):
            entries=[]
            for i in range(14):
                if formatted:
                    item={'key':i,'values':[{'cpu':0,'value':2},{'cpu':1,'value':3}]}
                    entries.append({'formatted':item})
                else:
                    key=list(i.to_bytes(4,'little'))
                    entries.append({'key':[hex(b) for b in key], 'values':[
                        {'cpu':0,'value':['0x02']+['0x00']*7},
                        {'cpu':1,'value':['0x03']+['0x00']*7}]})
            with patch.object(ctl,'bpf',return_value=entries):
                self.assertEqual(ctl.snapshot(),{name:5 for name in ctl.NAMES})

    def test_missing_counter_rejected(self):
        with patch.object(ctl,'bpf',return_value=[]), self.assertRaises(RuntimeError):
            ctl.snapshot()

    def test_csv_is_clean_and_has_15_columns(self):
        args=types.SimpleNamespace(csv=True,once=True,count=0,interval=1)
        with patch.object(ctl,'check_maps',return_value={'id':42}), patch.object(ctl,'program',return_value={'id':42}), patch.object(ctl,'snapshot',return_value=dict.fromkeys(ctl.NAMES,0)):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): ctl.cmd_stats(args)
        lines=output.getvalue().splitlines()
        self.assertEqual(len(lines),2)
        self.assertEqual(lines[0], 'timestamp_ns,'+','.join(ctl.NAMES))
        self.assertEqual(len(lines[1].split(',')),15)

    def test_json_stats_is_clean(self):
        args=types.SimpleNamespace(csv=False,once=True,count=0,interval=1)
        with patch.object(ctl,'check_maps',return_value={'id':42}), patch.object(ctl,'program',return_value={'id':42}), patch.object(ctl,'snapshot',return_value=dict.fromkeys(ctl.NAMES,0)):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): ctl.cmd_stats(args)
        self.assertEqual(json.loads(output.getvalue())['seen'],0)

    def test_route_guard(self):
        with patch.object(ctl,'command',return_value='[{"dst":"default","dev":"eth0"}]'), self.assertRaises(RuntimeError):
            ctl.guard('eth0')
        route='[{"dst":"default","nexthops":[{"dev":"eth1"}]}]'
        with patch.object(ctl,'command',return_value=route), self.assertRaises(RuntimeError): ctl.guard('eth1')

    def test_detach_uses_expected_fd(self):
        observed=[]
        def detach(index,flags,opts):
            p=ctypes.cast(opts,ctypes.POINTER(ctl.AttachOptions)).contents
            observed.append((index,flags,p.old_prog_fd,p.sz));return 0
        xdp=ctl.XDP.__new__(ctl.XDP)
        xdp.lib=types.SimpleNamespace(bpf_xdp_detach=detach)
        xdp.detach(4,11,'native')
        self.assertEqual(observed,[(4,4,11,ctypes.sizeof(ctl.AttachOptions))])

    def test_attach_cannot_overwrite(self):
        observed=[]
        xdp=ctl.XDP.__new__(ctl.XDP)
        xdp.lib=types.SimpleNamespace(bpf_xdp_attach=lambda i,f,flags,o: observed.append(flags) or 0)
        xdp.attach(4,11,'generic')
        self.assertEqual(observed,[3])

    def test_old_watchdog_token_does_nothing(self):
        with patch.object(ctl,'read_state',return_value={'token':'new'}), patch.object(ctl,'XDP') as x:
            ctl.cmd_watchdog(types.SimpleNamespace(token='old',ready_fd=0))
            x.assert_not_called()

    def test_state_is_atomic_and_clearable(self):
        with tempfile.TemporaryDirectory() as work, patch.object(ctl,'STATE',Path(work)/'state.json'):
            ctl.write_state({'token':'one'})
            self.assertEqual(ctl.read_state(),{'token':'one'})
            ctl.clear_state();self.assertIsNone(ctl.read_state())

    def test_watchdog_native_expiry(self):
        state={'token':'one','prog_id':42,'iface':'veth0','ifindex':4,'mode':'native','deadline':0}
        x=unittest.mock.Mock();x.fd.return_value=11;x.query.return_value=42
        with patch.object(ctl,'read_state',return_value=state), patch.object(ctl,'XDP',return_value=x), patch.object(ctl,'locked',return_value=contextlib.nullcontext()), patch.object(ctl,'clear_state') as clear, patch.object(ctl.os,'write'), patch.object(ctl.os,'close'), patch.object(ctl.socket,'if_nametoindex',return_value=4):
            ctl.cmd_watchdog(types.SimpleNamespace(token='one',ready_fd=99))
            x.detach.assert_called_once_with(4,11,'native');clear.assert_called_once()

    def test_watchdog_preserves_replacement_program(self):
        state={'token':'one','prog_id':42,'iface':'veth0','ifindex':4,'mode':'generic','deadline':0}
        x=unittest.mock.Mock();x.fd.return_value=11;x.query.return_value=999
        with patch.object(ctl,'read_state',return_value=state), patch.object(ctl,'XDP',return_value=x), patch.object(ctl,'locked',return_value=contextlib.nullcontext()), patch.object(ctl,'clear_state'), patch.object(ctl.os,'write'), patch.object(ctl.os,'close'), patch.object(ctl.socket,'if_nametoindex',return_value=4):
            ctl.cmd_watchdog(types.SimpleNamespace(token='one',ready_fd=99))
            x.detach.assert_not_called()

    def test_load_rolls_back_created_directory(self):
        with tempfile.TemporaryDirectory() as work:
            obj=Path(work)/'test.o';obj.write_bytes(b'placeholder')
            pins=Path(work)/'pins'
            def fake_load(args, **kwargs):
                (pins/'prog').write_text('fake pin')
                raise RuntimeError('simulated load failure')
            with patch.object(ctl,'PIN',pins), patch.object(ctl,'locked',return_value=contextlib.nullcontext()), patch.object(ctl.os.path,'ismount',return_value=True), patch.object(ctl,'command',side_effect=fake_load), self.assertRaises(RuntimeError):
                ctl.cmd_load(types.SimpleNamespace(obj=obj))
            self.assertFalse(pins.exists())

    def test_live_config_is_refused(self):
        args=types.SimpleNamespace(src_rate=50,src_burst=5,glob_rate=0,glob_burst=1)
        with patch.object(ctl,'locked',return_value=contextlib.nullcontext()), patch.object(ctl,'check_maps',return_value={'id':42}), patch.object(ctl,'XDP'), patch.object(ctl,'attachments',return_value=[{'prog_id':42}]), self.assertRaises(RuntimeError):
            ctl.cmd_config(args)

if __name__=='__main__': unittest.main()
