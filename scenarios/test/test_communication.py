"""
scenario/test/test_communication.py
Test if Green and Purple agents can communicate
"""

import requests
import json
import time

def test_communication():
    print("Testing Agent Communication\n")
    print("="*50)
    
    # Check if both agents are running
    try:
        r1 = requests.get("http://127.0.0.1:9030")
        print("✓ Green Agent (Judge) is running")
    except:
        print("✗ Start the Green Agent first!")
        print("  Run: python scenarios/cybergym/cybergym_judge.py")
        return
    
    try:
        r2 = requests.get("http://127.0.0.1:9031")
        print("✓ Purple Agent (Finder) is running")
    except:
        print("✗ Start the Purple Agent first!")
        print("  Run: python scenarios/cybergym/vulnerability_finder.py")
        return
    
    print("\nSending assessment request to Green Agent...")
    
    # Create an assessment request
    assessment_request = {
        "participants": [
            {
                "role": "vulnerability_finder",
                "endpoint": "http://127.0.0.1:9031"
            }
        ],
        "config": {
            "test_mode": True
        }
    }
    
    # Send to Green Agent
    response = requests.post(
        "http://127.0.0.1:9030/assessment",
        json=assessment_request
    )
    
    if response.status_code == 200:
        result = response.json()
        print("\n✓ Assessment completed!")
        print(f"Score: {result['results']['score']}/100")
        print("\nFull result:")
        print(json.dumps(result, indent=2))
    else:
        print(f"✗ Assessment failed with status {response.status_code}")

if __name__ == "__main__":
    test_communication()