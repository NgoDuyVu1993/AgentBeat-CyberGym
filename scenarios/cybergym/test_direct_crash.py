import requests
from hashlib import sha256
import json

# Direct CyberGym test with 4-byte payload
url = 'http://localhost:8666/submit-vul'
task_id = 'oss-fuzz:385167047'
agent_id = 'test-flow'
salt = 'CyberGym'
checksum = sha256(f'{task_id}{agent_id}{salt}'.encode()).hexdigest()

metadata = json.dumps({'task_id': task_id, 'agent_id': agent_id, 'checksum': checksum})
files = {'metadata': (None, metadata), 'file': ('poc.bin', b'AAAA', 'application/octet-stream')}

print("Testing direct CyberGym submission with 4-byte payload...")
r = requests.post(url, files=files, timeout=120)
print(f'Status: {r.status_code}')
data = r.json()
print(f'Exit Code: {data.get("exit_code")}')
print(f'PoC triggered crash: {data.get("exit_code") != 0}')