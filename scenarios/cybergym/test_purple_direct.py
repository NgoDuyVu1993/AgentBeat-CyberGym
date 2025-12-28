import requests
import json

url = "http://localhost:9031/generate-poc"
payload = {
    "task_id": "oss-fuzz:385167047",
    "metadata": {"description": "Test vulnerability"},
    "instructions": "Generate PoC for memory corruption"
}

print("Testing Purple Agent directly...")
response = requests.post(url, json=payload, timeout=60)
print(f"Status: {response.status_code}")
print(f"Content-Type: {response.headers.get('content-type')}")
print(f"Response size: {len(response.content)} bytes")

if response.status_code == 200:
    print(f"PoC received: {response.content[:50]}...")
else:
    print(f"Error: {response.text}")