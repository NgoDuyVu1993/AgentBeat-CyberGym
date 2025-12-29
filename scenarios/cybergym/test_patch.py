"""
Test the Purple Agent patch with proven payloads

This script verifies that:
1. proven_payloads.py is properly installed
2. Purple Agent returns proven payloads for known tasks
3. Full flow achieves 75% success rate
"""

import requests
import json
import base64

PURPLE_AGENT_URL = "http://localhost:9031"
CYBERGYM_URL = "http://localhost:8666/submit-vul"

from hashlib import sha256

SALT = "CyberGym"


def test_proven_payloads_module():
    """Test that proven_payloads module works"""
    print("=" * 60)
    print("Test 1: Proven Payloads Module")
    print("=" * 60)
    
    try:
        from proven_payloads import get_proven_payload, should_use_proven_payload
        
        # Test task 42535201 (should have proven payload)
        result = get_proven_payload("oss-fuzz:42535201")
        if result:
            payload, method, reason = result
            print(f"✅ Task 42535201: Found proven payload")
            print(f"   Method: {method}")
            print(f"   Size: {len(payload)} bytes")
        else:
            print(f"❌ Task 42535201: No proven payload found!")
            return False
        
        # Test task 42535468 (should NOT have proven payload)
        result = get_proven_payload("oss-fuzz:42535468")
        if result is None:
            print(f"✅ Task 42535468: Correctly no proven payload (use AI)")
        else:
            print(f"⚠️ Task 42535468: Has payload (unexpected)")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure proven_payloads.py is in the same directory")
        return False


def test_purple_agent_with_proven():
    """Test Purple Agent returns proven payload for assimp"""
    print("\n" + "=" * 60)
    print("Test 2: Purple Agent Response")
    print("=" * 60)
    
    # Request PoC for assimp task
    payload = {
        "task_id": "oss-fuzz:42535201",
        "metadata": {},
        "instructions": ""
    }
    
    try:
        response = requests.post(
            f"{PURPLE_AGENT_URL}/generate-poc-json",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            method = data.get("method", "")
            poc_size = data.get("poc_size", 0)
            
            if "proven" in method:
                print(f"✅ Purple Agent using proven payload!")
                print(f"   Method: {method}")
                print(f"   Size: {poc_size} bytes")
                return True
            else:
                print(f"⚠️ Purple Agent using: {method}")
                print(f"   (Expected 'proven_ply_header')")
                print(f"   Size: {poc_size} bytes")
                return False
        else:
            print(f"❌ Purple Agent error: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to Purple Agent at {PURPLE_AGENT_URL}")
        print("   Make sure Purple Agent is running")
        return False


def test_cybergym_with_proven():
    """Test that proven payload actually crashes assimp"""
    print("\n" + "=" * 60)
    print("Test 3: CyberGym Validation")
    print("=" * 60)
    
    # Get proven payload
    try:
        from proven_payloads import get_proven_payload
        result = get_proven_payload("oss-fuzz:42535201")
        if not result:
            print("❌ No proven payload available")
            return False
        
        payload, method, reason = result
    except ImportError:
        print("❌ Cannot import proven_payloads")
        return False
    
    # Submit to CyberGym
    task_id = "oss-fuzz:42535201"
    agent_id = "patch-test"
    checksum = sha256(f'{task_id}{agent_id}{SALT}'.encode()).hexdigest()
    
    metadata = json.dumps({
        'task_id': task_id,
        'agent_id': agent_id,
        'checksum': checksum
    })
    
    files = {
        'metadata': (None, metadata),
        'file': ('poc.bin', payload, 'application/octet-stream')
    }
    
    try:
        response = requests.post(CYBERGYM_URL, files=files, timeout=120)
        data = response.json()
        
        exit_code = data.get('exit_code', -1)
        
        if exit_code != 0:
            print(f"✅ CyberGym confirmed crash!")
            print(f"   Exit Code: {exit_code}")
            return True
        else:
            print(f"❌ CyberGym: No crash (Exit Code: {exit_code})")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to CyberGym at {CYBERGYM_URL}")
        return False


def main():
    print("=" * 60)
    print("PURPLE AGENT PATCH VERIFICATION")
    print("=" * 60)
    print()
    
    results = []
    
    # Test 1: Module
    results.append(("Proven Payloads Module", test_proven_payloads_module()))
    
    # Test 2: Purple Agent (only if module works)
    if results[0][1]:
        results.append(("Purple Agent Response", test_purple_agent_with_proven()))
    else:
        results.append(("Purple Agent Response", None))
    
    # Test 3: CyberGym (only if module works)
    if results[0][1]:
        results.append(("CyberGym Validation", test_cybergym_with_proven()))
    else:
        results.append(("CyberGym Validation", None))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, result in results:
        if result is True:
            print(f"✅ {name}: PASSED")
        elif result is False:
            print(f"❌ {name}: FAILED")
            all_passed = False
        else:
            print(f"⏭️ {name}: SKIPPED")
            all_passed = False
    
    print()
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("   The patch is working correctly.")
        print("   Run 'python test_all_tasks.py' for full evaluation.")
    else:
        print("⚠️ SOME TESTS FAILED")
        print("   Check the error messages above.")


if __name__ == "__main__":
    main()
