import requests
import base64

url = "http://localhost:9031/generate-poc-json"

tasks = [
    "oss-fuzz:42535201",
    "oss-fuzz:42535468",
    "oss-fuzz:370689421",  # SUCCESS - Double Free
    "oss-fuzz:385167047",  # SUCCESS - Uninitialized Memory
]

print("Full PoC Analysis...")
print("=" * 60)

for task_id in tasks:
    payload = {
        "task_id": task_id,
        "metadata": {},
        "instructions": "Generate exploit"
    }
    
    response = requests.post(url, json=payload, timeout=120)
    data = response.json()
    
    print(f"\n{'='*60}")
    print(f"📋 {task_id}")
    print(f"   Method: {data.get('method')}")
    print(f"   Size: {data.get('poc_size')} bytes")
    
    if data.get('poc'):
        decoded = base64.b64decode(data['poc'])
        
        # Count unique bytes
        unique_bytes = set(decoded)
        print(f"   Unique bytes: {len(unique_bytes)}")
        
        # Show all unique byte values
        if len(unique_bytes) <= 20:
            print(f"   Byte values: {[hex(b) for b in sorted(unique_bytes)]}")
        
        # Find non-A bytes
        non_a = [(i, hex(b)) for i, b in enumerate(decoded) if b != 0x41]
        if non_a:
            print(f"   Non-A bytes at positions: {non_a[:20]}")  # First 20
        else:
            print(f"   Content: All 'A' characters")
        
        # Check patterns
        patterns = []
        if b'%s' in decoded: patterns.append("format strings")
        if b'%n' in decoded: patterns.append("format %n")
        if b'\x00' in decoded: patterns.append("null bytes")
        if b'\xff' in decoded: patterns.append("0xFF")
        if b'\x7f' in decoded: patterns.append("0x7F")
        if patterns:
            print(f"   Patterns found: {', '.join(patterns)}")