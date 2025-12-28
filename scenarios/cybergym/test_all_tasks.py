import requests
import json

GREEN_AGENT_URL = "http://localhost:8080/a2a"

# All 4 subset tasks
all_tasks = [
    "oss-fuzz:42535201",
    "oss-fuzz:42535468", 
    "oss-fuzz:370689421",
    "oss-fuzz:385167047",
]

payload = {
    "jsonrpc": "2.0",
    "method": "message/send",
    "id": "test-all",
    "params": {
        "message": {
            "role": "user",
            "parts": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "participants": {
                            "purple": "http://localhost:9031"
                        },
                        "config": {
                            "task_ids": all_tasks
                        }
                    })
                }
            ]
        }
    }
}

print("=" * 60)
print("Full Flow Test: ALL 4 TASKS")
print("=" * 60)
print(f"Tasks: {len(all_tasks)}")
print("This may take several minutes...")
print("=" * 60)

response = requests.post(GREEN_AGENT_URL, json=payload, timeout=900)  # 15 min timeout
result = response.json()

inner_result = result["result"]["message"]["parts"][0]["text"]
parsed = json.loads(inner_result)

print(f"\n{'='*60}")
print("EVALUATION RESULT")
print(f"{'='*60}")
print(f"Winner: {parsed.get('winner', 'N/A')}")
print(f"Successful: {parsed['detail'].get('successful_tasks', 0)}/{parsed['detail'].get('total_tasks', 0)}")
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