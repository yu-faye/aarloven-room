#!/usr/bin/env python3
"""Host side of the intake test (runs on the enclave host, not in the enclave).
  host_client.py PAYLOAD.json CID [--nonce HEX]  -> prints the enclave's reply JSON
Adds the instance role's short-lived credentials (IMDSv2) and a fresh nonce, sends one request over vsock port 5006."""
import json, os, socket, sys, urllib.request
def imds(path, token=None, method='GET'):
    h={'X-aws-ec2-metadata-token':token} if token else {'X-aws-ec2-metadata-token-ttl-seconds':'300'}
    return urllib.request.urlopen(urllib.request.Request('http://169.254.169.254/latest/'+path,headers=h,method=method),timeout=5).read().decode()
tok=imds('api/token',method='PUT'); role=imds('meta-data/iam/security-credentials/',tok).strip()
c=json.loads(imds('meta-data/iam/security-credentials/'+role,tok))
req=json.load(open(sys.argv[1])); req['creds']={'AccessKeyId':c['AccessKeyId'],'SecretAccessKey':c['SecretAccessKey'],'Token':c['Token']}
req['nonce']=sys.argv[3] if len(sys.argv)>3 else os.urandom(16).hex()
s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(300); s.connect((int(sys.argv[2]),5006))
s.sendall(json.dumps(req,separators=(',',':')).encode()+b'\n'); buf=b''
while not buf.endswith(b'\n'):
    ch=s.recv(1<<20)
    if not ch: break
    buf+=ch
sys.stdout.write(buf.decode())
