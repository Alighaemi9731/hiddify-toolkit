#!/usr/bin/env python3
"""Linux/root integration: real packets, independent namespaces, no host firewall edits."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

spec=importlib.util.spec_from_file_location('toolkit',Path(__file__).resolve().parents[1]/'lib/toolkit.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

def cmd(args, data=None, check=True):
    p=subprocess.run(args,input=data,capture_output=True,text=True,timeout=15)
    if check and p.returncode:raise RuntimeError(str(args)+': '+p.stderr)
    return p.stdout.strip()


def main():
    if os.geteuid()!=0:raise SystemExit('Run as root on Linux')
    suffix=uuid.uuid4().hex[:7];names=['ht-g-'+suffix,'ht-e-'+suffix,'ht-c-'+suffix];gw,edge,client=names
    procs=[]
    def ns(name,args,data=None):return cmd(['ip','netns','exec',name]+args,data)
    def curl(name,url):return ns(name,['curl','--noproxy','*','-fsS','--connect-timeout','2','--max-time','5',url])
    server='''from http.server import BaseHTTPRequestHandler,HTTPServer
import sys
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(self.client_address[0].encode())
 def log_message(self,*args):pass
if len(sys.argv)>2:
 import socket
 class Server(HTTPServer):
  address_family=socket.AF_INET6
  def server_bind(self):self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);super().server_bind()
 Server(('::',int(sys.argv[1])),Handler).serve_forever()
else:HTTPServer(('0.0.0.0',int(sys.argv[1])),Handler).serve_forever()
'''
    conf={'aliases':[[18081,80],[18443,443]],'outbound':{'source':'198.18.0.1','ip':'198.18.0.10','interface':'eth0'}}
    passed=[]
    try:
        for name in names:cmd(['ip','netns','add',name]);ns(name,['ip','link','set','lo','up'])
        for a,b,local,remote in [(gw,edge,'198.18.0.1/24','198.18.0.2/24'),(gw,client,'10.9.0.1/24','10.9.0.2/24')]:
            left='v'+uuid.uuid4().hex[:8];right='v'+uuid.uuid4().hex[:8]
            cmd(['ip','link','add',left,'type','veth','peer','name',right])
            cmd(['ip','link','set',left,'netns',a]);cmd(['ip','link','set',right,'netns',b])
            dev='eth0' if b==edge else 'lan0'
            ns(a,['ip','link','set',left,'name',dev]);ns(b,['ip','link','set',right,'name','eth0'])
            for node,iface,address in [(a,dev,local),(b,'eth0',remote)]:
                ns(node,['ip','addr','add',address,'dev',iface]);ns(node,['ip','link','set',iface,'up'])
        ns(gw,['ip','addr','add','198.18.0.10/24','dev','eth0'])
        ns(gw,['ip','-6','addr','add','2001:db8::1/64','dev','eth0','nodad'])
        ns(edge,['ip','-6','addr','add','2001:db8::2/64','dev','eth0','nodad'])
        ns(client,['ip','route','add','default','via','10.9.0.1'])
        ns(edge,['ip','route','add','10.9.0.0/24','via','198.18.0.1'])
        ns(gw,['sysctl','-w','net.ipv4.ip_forward=1'])
        for node,port in [(gw,80),(gw,443),(edge,18080),(edge,18081)]:
            procs.append(subprocess.Popen(['ip','netns','exec',node,'python3','-u','-c',server,str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen(['ip','netns','exec',gw,'python3','-u','-c',server,'80','ipv6'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        assert curl(gw,'http://198.18.0.2:18080/')=='198.18.0.1'
        ns(gw,['nft','-f','-'],t.network_script('port-alias',conf)+t.network_script('outbound-ip',conf))
        assert curl(gw,'http://198.18.0.2:18080/')=='198.18.0.10';passed.append('outbound source changed to assigned secondary')
        assert curl(edge,'http://198.18.0.1:18081/')=='198.18.0.2';passed.append('incoming legacy HTTP port and reply source intact')
        assert curl(edge,'http://198.18.0.1:18443/')=='198.18.0.2';passed.append('legacy TLS gateway port mapped to 443')
        assert curl(gw,'http://127.0.0.1:18081/')=='127.0.0.1';passed.append('local destination excluded from SNAT; loopback alias works')
        assert curl(client,'http://198.18.0.2:18081/')=='10.9.0.2';passed.append('forwarded VPN traffic not intercepted or SNATed')
        assert curl(edge,'http://[2001:db8::1]:18081/')=='2001:db8::2';passed.append('IPv6 alias works; IPv4 SNAT does not affect IPv6')
        ns(gw,['iptables','-t','nat','-A','PREROUTING','-p','tcp','--dport','18081','-j','REDIRECT','--to-ports','444'])
        refused=subprocess.run(['ip','netns','exec',edge,'curl','--noproxy','*','-fsS','--max-time','3','http://198.18.0.1:18081/'],capture_output=True)
        assert refused.returncode!=0,'Toolkit overrode native panel DNAT'
        ns(gw,['iptables','-t','nat','-D','PREROUTING','-p','tcp','--dport','18081','-j','REDIRECT','--to-ports','444'])
        assert curl(edge,'http://198.18.0.1:18081/')=='198.18.0.2';passed.append('native panel DNAT takes precedence over toolkit aliases')
        before=ns(gw,['nft','-s','list','table','inet','hiddify_toolkit_ports'])
        ns(gw,['iptables','-t','nat','-F'])
        ns(gw,['iptables-restore'],'*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n')
        assert ns(gw,['nft','-s','list','table','inet','hiddify_toolkit_ports'])==before
        assert curl(edge,'http://198.18.0.1:18081/')=='198.18.0.2'
        assert curl(gw,'http://198.18.0.2:18080/')=='198.18.0.10';passed.append('both owned tables survive iptables flush/restore')
        ns(gw,['nft','delete','table','ip','hiddify_toolkit_egress'])
        assert curl(gw,'http://198.18.0.2:18080/')=='198.18.0.1'
        assert curl(edge,'http://198.18.0.1:18081/')=='198.18.0.2';passed.append('outbound revert preserves port alias')
        ns(gw,['nft','delete','table','inet','hiddify_toolkit_ports'])
        assert curl(edge,'http://198.18.0.1:80/')=='198.18.0.2';passed.append('revert leaves original gateway answering')
        print(json.dumps({'passed':passed,'count':len(passed)},indent=2))
    finally:
        for p in procs:p.terminate()
        for p in procs:
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        for name in reversed(names):cmd(['ip','netns','delete',name],check=False)

if __name__=='__main__':main()
