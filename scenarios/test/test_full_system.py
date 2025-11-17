"""
Test the complete system with mock server
"""

import requests
import json
import time

def test_full_system():
    print("Testing Complete CyberGym System")
    print("="*50)
    
    # 1. Check all services
    services = [
        ("Green Agent", "http://127.0.0.1:9030"),
        ("Purple Agent", "http://127.0.0.1:9031"),
        ("Mock Server", "http://127.0.0.1:8666")
    ]
    
    for name, url in services:
        try:
            r = requests.get(url, timeout=2)
            print(f"✓ {name} is running at {url}")
        except:
            print(f"✗ {name} is NOT running! Start it first:")
            if "Green" in name:
                print("  python scenarios/cybergym/cybergym_judge.py")
            elif "Purple" in name:
                print("  python scenarios/cybergym/vulnerability_finder.py")
            else:
                print("  python mock_server.py")
            return
    
    print("\n" + "="*50)
    print("Sending assessment request...")
    
    # 2. Create assessment request with multiple tasks
    assessment_request = {
    "participants": [
        {
            "role": "vulnerability_finder",
            "endpoint": "http://127.0.0.1:9031",
            "agent_id": "vulnerability_finder_v1"
        }
    ],
    "config": {
        "task_ids": [
            "arvo:10400",   
            "arvo:3938",    
            "arvo:47101",
            "arvo:24993",
            "arvo:1065",
            "arvo:368",          # Hard one - should fail
            "oss-fuzz:42535201"  # Hard one - should fail
        ]
    }
}
    
    # 3. Send assessment
    response = requests.post(
        "http://127.0.0.1:9030/assessment",
        json=assessment_request
    )
    
    if response.status_code == 200:
        result = response.json()
        print("\n✓ Assessment completed!")
        print(f"Tasks Evaluated: {result['tasks_evaluated']}")
        print(f"Average Score: {result['average_score']:.1f}/100")
        
        print("\nPer-task results:")
        for task_result in result['results']:
            task_id = task_result['task_id']
            score = task_result['score']
            print(f"  - {task_id}: {score}/100")
        
        # Check mock server stats
        stats_response = requests.get("http://127.0.0.1:8666/stats")
        if stats_response.status_code == 200:
            stats = stats_response.json()
            print(f"\nMock Server Stats:")
            print(f"  Total submissions: {stats['total_submissions']}")
            print(f"  Successful exploits: {stats['successful_exploits']}")
    else:
        print(f"✗ Assessment failed with status {response.status_code}")

if __name__ == "__main__":
    test_full_system()