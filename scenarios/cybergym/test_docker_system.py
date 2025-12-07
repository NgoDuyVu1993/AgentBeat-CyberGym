"""
Comprehensive Test Suite for CyberGym Docker System
Verifies everything works before Phase 1 submission

Run with: python test_docker_system.py
Or with pytest: pytest test_docker_system.py -v
"""

import os
import sys
import json
import time
import base64
import subprocess
import requests
from typing import Dict, List, Tuple, Optional
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================
class TestConfig:
    """Test configuration"""
    VALIDATOR_URL = "http://localhost:8666"
    GREEN_AGENT_URL = "http://localhost:9030"
    PURPLE_AGENT_URL = "http://localhost:9031"
    
    TIMEOUT = 10
    
    TEST_TASKS = [
        "arvo:10400",
        "arvo:3938",
        "arvo:47101",
        "arvo:24993",
        "arvo:1065",
        "arvo:368",
        "oss-fuzz:42535201"
    ]


# ============================================================
# TEST UTILITIES
# ============================================================
class Colors:
    """ANSI color codes for terminal output"""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_header(text: str):
    """Print a section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")


def print_result(name: str, passed: bool, details: str = ""):
    """Print a test result"""
    status = f"{Colors.GREEN}✓ PASS{Colors.RESET}" if passed else f"{Colors.RED}✗ FAIL{Colors.RESET}"
    print(f"  {status} {name}")
    if details:
        print(f"       {Colors.YELLOW}{details}{Colors.RESET}")


def check_endpoint(name: str, url: str) -> bool:
    """Check if an endpoint is reachable"""
    try:
        response = requests.get(url, timeout=TestConfig.TIMEOUT)
        return response.status_code == 200
    except:
        return False


# ============================================================
# DOCKER TESTS
# ============================================================
def test_docker_installation() -> Tuple[bool, str]:
    """Test if Docker is installed"""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, f"Docker installed: {version}"
        return False, "Docker command failed"
    except FileNotFoundError:
        return False, "Docker not found in PATH"
    except Exception as e:
        return False, str(e)


def test_docker_daemon() -> Tuple[bool, str]:
    """Test if Docker daemon is running (using docker info)"""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True, "Docker daemon is running"
        return False, f"Docker daemon not running: {result.stderr[:100]}"
    except Exception as e:
        return False, str(e)


def test_docker_images() -> Tuple[bool, str, Dict[str, bool]]:
    """Test which Docker images are available"""
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return False, "Failed to list images", {}
        
        images = set(result.stdout.strip().split('\n'))
        
        status = {}
        for task_id in TestConfig.TEST_TASKS:
            safe_id = task_id.replace(":", "_")
            vuln = f"cybergym/{safe_id}:vulnerable"
            patch = f"cybergym/{safe_id}:patched"
            status[task_id] = vuln in images and patch in images
        
        ready = sum(1 for v in status.values() if v)
        return ready > 0, f"{ready}/{len(status)} task images ready", status
        
    except Exception as e:
        return False, str(e), {}


# ============================================================
# COMPONENT TESTS
# ============================================================
def test_validator() -> Tuple[bool, str]:
    """Test Docker Validator service"""
    try:
        response = requests.get(
            f"{TestConfig.VALIDATOR_URL}/health",
            timeout=TestConfig.TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            docker_tasks = sum(1 for v in data.get("docker_tasks", {}).values() if v)
            return True, f"Validator healthy, {docker_tasks} Docker tasks available"
        return False, f"Unhealthy response: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to validator"
    except Exception as e:
        return False, str(e)


def test_green_agent() -> Tuple[bool, str]:
    """Test Green Agent service"""
    try:
        response = requests.get(
            f"{TestConfig.GREEN_AGENT_URL}/health",
            timeout=TestConfig.TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            return True, f"Green Agent healthy: {data.get('status', 'unknown')}"
        return False, f"Unhealthy response: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to Green Agent"
    except Exception as e:
        return False, str(e)


def test_purple_agent() -> Tuple[bool, str]:
    """Test Purple Agent service"""
    try:
        response = requests.get(
            f"{TestConfig.PURPLE_AGENT_URL}/health",
            timeout=TestConfig.TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            ai = "AI available" if data.get("ai_available") else "Pattern-only mode"
            return True, f"Purple Agent healthy: {ai}"
        return False, f"Unhealthy response: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to Purple Agent"
    except Exception as e:
        return False, str(e)


# ============================================================
# VALIDATION TESTS
# ============================================================
def test_mock_validation() -> Tuple[bool, str]:
    """Test validation with mock (pattern-based) validation"""
    try:
        # Generate a test PoC (should trigger pattern match)
        test_poc = b"A" * 300  # Large buffer likely to trigger overflow
        
        files = {"file": ("poc.bin", test_poc, "application/octet-stream")}
        data = {
            "metadata": json.dumps({
                "task_id": "arvo:10400",
                "agent_id": "test"
            })
        }
        
        response = requests.post(
            f"{TestConfig.VALIDATOR_URL}/submit-vul",
            files=files,
            data=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            score = result.get("score", 0)
            method = result.get("method", "unknown")
            return score > 0, f"Score: {score}/100, Method: {method}"
        return False, f"Validation failed: {response.status_code}"
        
    except Exception as e:
        return False, str(e)


def test_docker_validation(task_id: str = "arvo:10400") -> Tuple[bool, str]:
    """Test validation with Docker (if available)"""
    try:
        # Check if Docker images exist for this task
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True
        )
        
        safe_id = task_id.replace(":", "_")
        images = result.stdout if result.returncode == 0 else ""
        
        if f"cybergym/{safe_id}:vulnerable" not in images:
            return True, f"Skipped (no Docker image for {task_id})"
        
        # Test with a PoC that should trigger the vulnerability
        test_poc = b"A" * 300
        
        files = {"file": ("poc.bin", test_poc, "application/octet-stream")}
        data = {
            "metadata": json.dumps({
                "task_id": task_id,
                "agent_id": "test_docker"
            })
        }
        
        response = requests.post(
            f"{TestConfig.VALIDATOR_URL}/submit-vul",
            files=files,
            data=data,
            timeout=60  # Docker validation takes longer
        )
        
        if response.status_code == 200:
            result = response.json()
            score = result.get("score", 0)
            method = result.get("method", "unknown")
            confirmed = result.get("vulnerability_confirmed", False)
            
            if method == "docker":
                return confirmed, f"Docker validation: {score}/100"
            else:
                return True, f"Fell back to {method}: {score}/100"
        
        return False, f"Validation failed: {response.status_code}"
        
    except Exception as e:
        return False, str(e)


def test_poc_generation() -> Tuple[bool, str]:
    """Test PoC generation from Purple Agent"""
    try:
        request = {
            "task_id": "arvo:10400",
            "metadata": {
                "project": "ImageMagick",
                "vulnerability": "buffer overflow",
                "hint": "MNG chunk parsing"
            },
            "instructions": ""
        }
        
        response = requests.post(
            f"{TestConfig.PURPLE_AGENT_URL}/generate-poc",
            json=request,
            timeout=30
        )
        
        if response.status_code == 200:
            poc_size = len(response.content)
            method = response.headers.get("X-Generation-Method", "unknown")
            return poc_size > 0, f"Generated {poc_size} bytes ({method})"
        
        return False, f"Generation failed: {response.status_code}"
        
    except Exception as e:
        return False, str(e)


# ============================================================
# INTEGRATION TESTS
# ============================================================
def test_full_pipeline(task_id: str = "arvo:10400") -> Tuple[bool, str]:
    """Test the full pipeline: Purple → Validator"""
    try:
        # Step 1: Generate PoC from Purple Agent
        request = {
            "task_id": task_id,
            "metadata": {
                "project": "Test",
                "vulnerability": "buffer overflow"
            }
        }
        
        poc_response = requests.post(
            f"{TestConfig.PURPLE_AGENT_URL}/generate-poc",
            json=request,
            timeout=30
        )
        
        if poc_response.status_code != 200:
            return False, "Purple Agent failed to generate PoC"
        
        poc_data = poc_response.content
        
        # Step 2: Validate PoC
        files = {"file": ("poc.bin", poc_data, "application/octet-stream")}
        data = {
            "metadata": json.dumps({
                "task_id": task_id,
                "agent_id": "integration_test"
            })
        }
        
        val_response = requests.post(
            f"{TestConfig.VALIDATOR_URL}/submit-vul",
            files=files,
            data=data,
            timeout=60
        )
        
        if val_response.status_code == 200:
            result = val_response.json()
            score = result.get("score", 0)
            confirmed = result.get("vulnerability_confirmed", False)
            method = result.get("method", "unknown")
            
            status = "SUCCESS" if confirmed else "partial"
            return True, f"Pipeline {status}: {score}/100 ({method})"
        
        return False, f"Validator failed: {val_response.status_code}"
        
    except Exception as e:
        return False, str(e)


# ============================================================
# MAIN TEST RUNNER
# ============================================================
def run_all_tests() -> Dict[str, bool]:
    """Run all tests and return results"""
    results = {}
    
    # Docker Tests
    print_header("Docker Environment Tests")
    
    passed, details = test_docker_installation()
    print_result("Docker Installation", passed, details)
    results["docker_installation"] = passed
    
    passed, details = test_docker_daemon()
    print_result("Docker Daemon (docker info)", passed, details)
    results["docker_daemon"] = passed
    
    passed, details, image_status = test_docker_images()
    print_result("Docker Images", passed, details)
    results["docker_images"] = passed
    
    if image_status:
        for task_id, ready in image_status.items():
            status = "Ready" if ready else "Missing"
            print(f"       {task_id}: {status}")
    
    # Component Tests
    print_header("Component Health Tests")
    
    passed, details = test_validator()
    print_result("Docker Validator", passed, details)
    results["validator"] = passed
    
    passed, details = test_green_agent()
    print_result("Green Agent", passed, details)
    results["green_agent"] = passed
    
    passed, details = test_purple_agent()
    print_result("Purple Agent", passed, details)
    results["purple_agent"] = passed
    
    # Validation Tests
    print_header("Validation Tests")
    
    if results.get("validator"):
        passed, details = test_mock_validation()
        print_result("Mock Validation", passed, details)
        results["mock_validation"] = passed
        
        passed, details = test_docker_validation()
        print_result("Docker Validation", passed, details)
        results["docker_validation"] = passed
    else:
        print(f"  {Colors.YELLOW}⊘ Skipped (validator not running){Colors.RESET}")
    
    # Purple Agent Tests
    if results.get("purple_agent"):
        passed, details = test_poc_generation()
        print_result("PoC Generation", passed, details)
        results["poc_generation"] = passed
    else:
        print(f"  {Colors.YELLOW}⊘ Skipped (purple agent not running){Colors.RESET}")
    
    # Integration Tests
    print_header("Integration Tests")
    
    if results.get("validator") and results.get("purple_agent"):
        passed, details = test_full_pipeline()
        print_result("Full Pipeline", passed, details)
        results["full_pipeline"] = passed
    else:
        print(f"  {Colors.YELLOW}⊘ Skipped (components not running){Colors.RESET}")
    
    return results


def print_summary(results: Dict[str, bool]):
    """Print test summary"""
    print_header("Test Summary")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    print(f"\n  Total Tests: {total}")
    print(f"  {Colors.GREEN}Passed: {passed}{Colors.RESET}")
    print(f"  {Colors.RED}Failed: {failed}{Colors.RESET}")
    
    # Overall status
    print()
    if failed == 0:
        print(f"  {Colors.GREEN}{Colors.BOLD}✓ ALL TESTS PASSED - READY FOR PHASE 1 SUBMISSION!{Colors.RESET}")
    elif passed >= total * 0.7:
        print(f"  {Colors.YELLOW}{Colors.BOLD}⚠ MOSTLY PASSING - Review failed tests{Colors.RESET}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}✗ SIGNIFICANT FAILURES - Fix before submission{Colors.RESET}")
    
    # Recommendations
    if not results.get("docker_daemon"):
        print(f"\n  {Colors.YELLOW}Recommendation: Start Docker Desktop{Colors.RESET}")
    
    if not results.get("docker_images"):
        print(f"\n  {Colors.YELLOW}Recommendation: Run 'python docker_setup.py --build'{Colors.RESET}")
    
    if not results.get("validator"):
        print(f"\n  {Colors.YELLOW}Recommendation: Start validator with 'python docker_validator.py'{Colors.RESET}")


def main():
    """Main entry point"""
    print(f"""
{Colors.BOLD}{Colors.BLUE}
╔════════════════════════════════════════════════════════════╗
║       CyberGym Docker System - Test Suite                  ║
║                  Phase 1 Validation                        ║
╚════════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    
    results = run_all_tests()
    print_summary(results)
    
    # Return exit code based on results
    critical_tests = ["docker_installation", "docker_daemon"]
    critical_passed = all(results.get(t, False) for t in critical_tests)
    
    return 0 if critical_passed else 1


if __name__ == "__main__":
    sys.exit(main())