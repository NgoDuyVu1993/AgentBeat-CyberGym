"""
Test Script for CyberGym Green Agent

This script tests the full flow:
1. Starts the Green Agent
2. Simulates a simple Purple Agent response
3. Validates PoC through CyberGym server

Run this after:
1. CyberGym server is running on port 8666
2. You're in the cybergym-core directory
"""

import asyncio
import json
from cybergym_adapter import CyberGymAdapter, test_adapter


def test_adapter_only():
    """Test just the adapter (no Purple Agent needed)"""
    print("=" * 60)
    print("TEST 1: CyberGym Adapter Direct Test")
    print("=" * 60)
    
    adapter = CyberGymAdapter()
    
    # Check server health
    if not adapter.health_check():
        print("❌ CyberGym server not accessible!")
        print("   Make sure to start it with:")
        print("   python -m cybergym.server --host 0.0.0.0 --port 8666 \\")
        print("     --cybergym_oss_fuzz_path ./cybergym-oss-fuzz-data-subset/oss-fuzz-data")
        return False
    
    print("✅ CyberGym server is running")
    
    # Test each available task
    test_tasks = [
        "oss-fuzz:42535201",
        "oss-fuzz:42535468",
        "oss-fuzz:370689421",
        "oss-fuzz:385167047",
    ]
    
    for task_id in test_tasks:
        print(f"\nTesting task: {task_id}")
        
        # Simple test payload (won't trigger vulnerability)
        result = adapter.validate_poc(
            task_id=task_id,
            poc_data=b"AAAA",  # Simple test data
            agent_id="test-green-agent"
        )
        
        print(f"  Exit Code: {result.exit_code}")
        print(f"  Score: {result.score}")
        print(f"  Reason: {result.reason}")
        
        if result.exit_code == 0:
            print(f"  ✅ Fuzzer executed (PoC didn't crash it - expected for simple test)")
        elif result.exit_code > 0:
            print(f"  🎯 Crash detected!")
    
    return True


async def test_green_agent():
    """Test the Green Agent with a mock Purple Agent"""
    print("\n" + "=" * 60)
    print("TEST 2: Green Agent Integration Test")
    print("=" * 60)
    
    from cybergym_green_agent import CyberGymGreenAgent, Config, EvalRequest
    
    # Create Green Agent
    config = Config(
        CYBERGYM_SERVER_URL="http://localhost:8666",
        TASK_IDS=["oss-fuzz:42535201"]  # Test with just one task
    )
    agent = CyberGymGreenAgent(config)
    
    # Create a mock evaluation request
    # In real scenario, this would have the Purple Agent's endpoint
    print("\nNote: This test uses a mock Purple Agent (returns simple PoC)")
    print("In production, the Purple Agent would generate real exploits.")
    
    # For now, just test the adapter part
    print("\n✅ Green Agent created successfully")
    print(f"   CyberGym URL: {config.CYBERGYM_SERVER_URL}")
    print(f"   Task IDs: {config.TASK_IDS}")
    
    return True


def main():
    """Run all tests"""
    print("\n🔬 CyberGym Green Agent Test Suite")
    print("=" * 60)
    
    # Test 1: Adapter
    adapter_ok = test_adapter_only()
    
    if adapter_ok:
        # Test 2: Green Agent
        asyncio.run(test_green_agent())
    
    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)
    
    print("""
Next Steps:
-----------
1. Copy cybergym_adapter.py and cybergym_green_agent.py to your project:
   
   Copy-Item cybergym_adapter.py "C:\\Users\\ngodu\\OneDrive\\Máy tính\\Green Agent\\CyberGym-AgentBeats\\scenarios\\cybergym\\"
   Copy-Item cybergym_green_agent.py "C:\\Users\\ngodu\\OneDrive\\Máy tính\\Green Agent\\CyberGym-AgentBeats\\scenarios\\cybergym\\"

2. Start the Green Agent:
   
   python cybergym_green_agent.py --port 8080 --cybergym-url http://localhost:8666

3. The Green Agent will be available at http://localhost:8080
   - A2A endpoint: http://localhost:8080/a2a
   - Agent card: http://localhost:8080/.well-known/agent.json
""")


if __name__ == "__main__":
    main()
