#!/usr/bin/env python3
"""Use the actual installed panel function with a controlled TLS server in a namespace."""
import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def main():
    if os.geteuid()!=0:raise SystemExit('Linux root required')
    root=Path('/opt/hiddify-manager/.venv313/lib/python3.13/site-packages/hiddifypanel')
    source=(root/'hutils/network/net.py').read_text()
    node=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef) and n.name=='is_domain_support_h2_tls13')
    function=ast.get_source_segment(source,node)
    name='ht-tls-'+uuid.uuid4().hex[:7]
    def run(args):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=20)
    try:
        run(['ip','netns','add',name]);run(['ip','-n',name,'link','set','lo','up'])
        with tempfile.TemporaryDirectory(prefix='ht-tls-') as d:
            base=Path(d);cert=base/'cert.pem';key=base/'key.pem'
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'])
            code='cert_path='+repr(str(cert))+'\nkey_path='+repr(str(key))+'\n'+'''import ssl,socket,time,threading,json,os
os.environ['SSL_CERT_FILE']=cert_path
FUNCTION
results=[]
for protocol,version in [('http/1.1',ssl.TLSVersion.TLSv1_3),('h2',ssl.TLSVersion.TLSv1_3),('http/1.1',ssl.TLSVersion.TLSv1_2)]:
 listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',443));listener.listen()
 selected=[]
 def serve():
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=version;context.maximum_version=version;context.load_cert_chain(cert_path,key_path);context.set_alpn_protocols([protocol])
  raw,_=listener.accept()
  with context.wrap_socket(raw,server_side=True) as peer:selected.append(peer.selected_alpn_protocol())
 thread=threading.Thread(target=serve);thread.start()
 accepted=is_domain_support_h2_tls13('localhost','127.0.0.1');thread.join(4);listener.close()
 assert accepted == (version==ssl.TLSVersion.TLSv1_3),(protocol,version,accepted)
 assert selected==[protocol],selected
 results.append({'alpn':protocol,'tls':str(version),'accepted':accepted})
print(json.dumps({'controlled_tls_checks':results}))
'''.replace('FUNCTION',function)
            script=base/'check.py';script.write_text(code)
            p=run(['ip','netns','exec',name,'python3',str(script)])
            print(p.stdout.strip())
    finally:subprocess.run(['ip','netns','delete',name],capture_output=True)

if __name__=='__main__':main()
