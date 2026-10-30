#!/usr/bin/env python3
"""Live low-rate veth functional acceptance. Requires a VM with ONE online CPU.
Resets and reattaches Kavach for each scenario, retains a JSON evidence report.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ctl',HERE.parent/'kavach_ctl.py')
ctl=importlib.util.module_from_spec(spec);spec.loader.exec_module(ctl)

def online_cpus(text):
    count=0
    for part in text.strip().split(','):
        ends=part.split('-')
        count += int(ends[-1])-int(ends[0])+1
    return count

def control(*args):
    subprocess.run(['python3',str(HERE.parent/'kavach_ctl.py'),*args],check=True)

def main():
    if os.geteuid()!=0: raise RuntimeError('Run with sudo')
    if online_cpus(Path('/sys/devices/system/cpu/online').read_text())!=1:
        raise RuntimeError('Acceptance requires ONE online CPU. Shut down the VM, select 1 vCPU, boot, then rerun.')
    info=json.loads(subprocess.check_output(['ip','-j','addr','show','dev','veth0'],text=True))[0]
    if '10.200.1.1' not in [a['local'] for a in info['addr_info']]:
        raise RuntimeError('Expected test address 10.200.1.1 on veth0')
    mac=info['address']
    report=HERE / 'evidence/a2-limiters.json'
    report.parent.mkdir(parents=True,exist_ok=True)
    scenarios=[
        ('below',50,5,0,1,'10.200.1.2','30',0),
        ('twice',50,5,0,1,'10.200.1.2','100',0),
        ('isolation',50,5,100,10,'10.200.1.2,10.200.1.3','500,20',0),
        ('burst',1,5,0,1,'10.200.1.2','1',6),
        ('global',0,1,50,5,'10.200.1.2','100',0),
        ('both',50,5,20,2,'10.200.1.2','100',0),
    ]
    results=[]
    for name,sr,sb,gr,gb,sources,rates,burst in scenarios:
        stop=threading.Event(); received={}; capture_errors=[]
        control('detach','--iface','veth0')
        control('unload');control('load')
        control('config','--src-rate',str(sr),'--src-burst',str(sb),'--glob-rate',str(gr),'--glob-burst',str(gb))
        # Raw receive counts establish legitimate-source success independently.
        receiver=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
        receiver.bind(('veth0',0));receiver.settimeout(0.1)
        def capture():
            try:
                while not stop.is_set():
                    try: data=receiver.recv(65535)
                    except socket.timeout: continue
                    if len(data)<42 or data[12:14]!=b'\x08\x00' or data[23]!=17: continue
                    offset=14+(data[14]&15)*4
                    if len(data)<offset+8 or data[offset+2:offset+4]!=b'\x00\x35': continue
                    source=socket.inet_ntoa(data[26:30]);received[source]=received.get(source,0)+1
            except Exception as error: capture_errors.append(str(error))
        worker=threading.Thread(target=capture);worker.start()
        try:
            control('attach','generic','--iface','veth0','--watchdog-minutes','2')
            before=ctl.snapshot()
            cmd=['ip','netns','exec','kavach-test','python3',str(HERE/'send_dns.py'),
                 '--dst-mac',mac,'--sources',sources,'--rates',rates,'--duration','10']
            if burst: cmd.extend(['--burst-count',str(burst)])
            sent=json.loads(subprocess.check_output(cmd,text=True))
            time.sleep(0.3)
            after=ctl.snapshot()
        finally:
            stop.set();worker.join();receiver.close()
            control('detach','--iface','veth0')
        delta={k:after[k]-before[k] for k in ctl.NAMES}
        passed=delta['dns_pass']; total=sum(sent['sent'].values())
        ok=not capture_errors and not delta['drop_busy'] and not delta['drop_state']
        if name=='below': ok &= passed>=0.98*total and delta['drop_src']==0
        elif name in ('twice','global'): ok &= 0.45 <= passed/total <= 0.56
        elif name=='both': ok &= 0.17<=passed/total<=0.24 and delta['drop_src']>0 and delta['drop_global']>0
        elif name=='isolation': ok &= received.get('10.200.1.3',0)>=0.98*sent['sent']['10.200.1.3'] and delta['drop_src']>0
        elif name=='burst': ok &= passed==5 and delta['drop_src']==1 and sent['elapsed_s']<0.5
        # Count partition includes non-DNS background traffic as well.
        ok &= delta['seen']==sum(v for k,v in delta.items() if k!='seen')
        result={'case':name,'pass':bool(ok),'sender':sent,'received_by_source':received,
                'counter_delta':delta,'capture_errors':capture_errors}
        results.append(result);report.write_text(json.dumps(results,indent=2))
        print(('PASS' if ok else 'FAIL')+': '+name,flush=True)
        if not ok: raise RuntimeError(f'{name} failed; inspect {report}')
    print('PASS: 6/6 live limiter scenarios. Native mode and multi-CPU kernel contention remain separate checks.')

if __name__=='__main__': main()
