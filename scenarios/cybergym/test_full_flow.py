"""
Test full flow: Green Agent -> Purple Agent -> CyberGym Server
"""
import requests
import json

GREEN_AGENT_URL = "http://localhost:8080/a2a"

payload = {
    "jsonrpc": "2.0",
    "method": "message/send",
    "id": "test-1",
    "params": {
        "message": {
            "role": "user",
            "parts": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "participants": {
                            "purple": "http://localhost:9031"  # Purple Agent port
                        },
                        "config": {
                            "task_ids": ["oss-fuzz:385167047"]  # Task that crashed with simple AAAA
                        }
                    })
                }
            ]
        }
    }
}

print("=" * 60)
print("Full Flow Test: Green Agent -> Purple Agent -> CyberGym")
print("=" * 60)
print(f"Green Agent: http://localhost:8080")
print(f"Purple Agent: http://localhost:9031")
print(f"CyberGym Server: http://localhost:8666")
print(f"Task: oss-fuzz:385167047")
print("=" * 60)
print("\nSending evaluation request...")
print("(This may take a few minutes for AI to generate exploit)\n")

try:
    response = requests.post(GREEN_AGENT_URL, json=payload, timeout=600)
    print(f"Status: {response.status_code}")
    
    result = response.json()
    
    # Pretty print the result
    if "result" in result:
        inner_result = result["result"]["message"]["parts"][0]["text"]
        parsed = json.loads(inner_result)
        print(f"\n{'='*60}")
        print("EVALUATION RESULT")
        print(f"{'='*60}")
        print(f"Winner: {parsed.get('winner', 'N/A')}")
        print(f"Total Tasks: {parsed['detail'].get('total_tasks', 0)}")
        print(f"Successful: {parsed['detail'].get('successful_tasks', 0)}")
        print(f"Score: {parsed['detail'].get('total_score', 0)}/{parsed['detail'].get('max_score', 0)}")
        print(f"Percentage: {parsed['detail'].get('percentage', 0)}%")
        
        print(f"\n{'='*60}")
        print("TASK DETAILS")
        print(f"{'='*60}")
        for task in parsed['detail'].get('task_results', []):
            status = "✅" if task['success'] else "❌"
            print(f"{status} {task['task_id']}")
            print(f"   Score: {task['score']}, Exit Code: {task['exit_code']}")
            print(f"   Reason: {task['reason']}")
            print(f"   PoC Size: {task['poc_size']} bytes")
    else:
        print(f"Response: {json.dumps(result, indent=2)}")
        
except requests.exceptions.Timeout:
    print("ERROR: Request timed out (10 minutes)")
except Exception as e:
    print(f"ERROR: {e}")