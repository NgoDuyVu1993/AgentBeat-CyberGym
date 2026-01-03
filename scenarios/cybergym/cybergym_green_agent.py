"""
CyberGym Green Agent - Official Server Integration

This Green Agent:
1. Receives tasks from AgentBeats
2. Sends tasks to Purple Agents (AI vulnerability exploiters)
3. Validates PoCs using the official CyberGym server
4. Reports scores back to AgentBeats
"""

import os
import json
import asyncio
import logging
import uuid
from typing import Any
from dataclasses import dataclass, asdict

import httpx
from pydantic import BaseModel, HttpUrl

# Import adapter
from cybergym_adapter import CyberGymAdapter, ValidationResult

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class Config:
    """Green Agent Configuration"""
    # CyberGym server
    CYBERGYM_SERVER_URL: str = os.getenv("CYBERGYM_SERVER_URL", "http://localhost:8666")
    
    # Task configuration
    TASK_IDS: list = None
    
    # Timeouts
    PURPLE_AGENT_TIMEOUT: int = 300  # 5 minutes for AI to generate PoC
    VALIDATION_TIMEOUT: int = 120    # 2 minutes for Docker validation
    
    def __post_init__(self):
        if self.TASK_IDS is None:
            # Default subset tasks (4 oss-fuzz vulnerabilities)
            self.TASK_IDS = [
                "oss-fuzz:42535201",
                "oss-fuzz:42535468",
                "oss-fuzz:370689421",
                "oss-fuzz:385167047",
            ]


# ============================================================================
# Models
# ============================================================================

class EvalRequest(BaseModel):
    """Request from AgentBeats to start evaluation"""
    participants: dict[str, HttpUrl]  # role -> endpoint mapping
    config: dict[str, Any]


class EvalResult(BaseModel):
       results: list[dict[str, Any]]  # List with "agent" field in each entry


@dataclass
class TaskResult:
    """Result for a single task"""
    task_id: str
    success: bool
    score: int
    exit_code: int
    reason: str
    poc_size: int = 0
    poc_id: str = ""


# ============================================================================
# Task Data Loader
# ============================================================================

class TaskDataLoader:
    """Load task descriptions from cybergym_data"""
    
    def __init__(self, data_path: str = "./cybergym_data"):
        self.data_path = data_path
        self.tasks_file = os.path.join(data_path, "tasks.json")
        self._tasks_cache = None
    
    def load_tasks(self) -> dict:
        """Load all tasks from tasks.json"""
        if self._tasks_cache is None:
            try:
                with open(self.tasks_file, 'r') as f:
                    self._tasks_cache = json.load(f)
            except FileNotFoundError:
                logger.warning(f"Tasks file not found: {self.tasks_file}")
                self._tasks_cache = {}
        return self._tasks_cache
    
    def get_task_description(self, task_id: str) -> dict:
        """Get description for a specific task"""
        tasks = self.load_tasks()
        
        # Parse task_id (e.g., "oss-fuzz:42535201" -> "42535201")
        if ":" in task_id:
            _, task_num = task_id.split(":", 1)
        else:
            task_num = task_id
        
        # Search in tasks
        for task in tasks.get("tasks", []):
            if str(task.get("id")) == task_num or task.get("task_id") == task_id:
                # Make sure task_id is included
                task["task_id"] = task_id
                return task
        
        # Return minimal info if not found
        return {
            "task_id": task_id,
            "description": f"Exploit vulnerability in {task_id}"
        }


# ============================================================================
# Purple Agent Client
# ============================================================================

class PurpleAgentClient:
    """Client to communicate with Purple Agents via REST API"""
    
    def __init__(self, endpoint: str, timeout: int = 300):
        self.endpoint = str(endpoint).rstrip('/')
        self.timeout = timeout
    
    async def request_poc(self, task_description: dict, assessment_id: str) -> bytes | None:
        """
        Request a PoC from the Purple Agent.
        
        Args:
            task_description: Vulnerability description to exploit
            assessment_id: Unique ID for this assessment
            
        Returns:
            Binary PoC data, or None if failed
        """
        # Get task_id from description
        task_id = task_description.get("task_id", assessment_id)
        
        # Build instructions from task description
        instructions = self._build_instructions(task_description)
        
        # Prepare request payload matching TaskRequest model
        payload = {
            "task_id": task_id,
            "metadata": task_description,
            "instructions": instructions
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Call /generate-poc endpoint (returns binary directly)
                response = await client.post(
                    f"{self.endpoint}/generate-poc",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    # Response is binary PoC directly
                    content_type = response.headers.get("content-type", "")
                    if "application/octet-stream" in content_type:
                        logger.info(f"Received binary PoC: {len(response.content)} bytes")
                        return response.content
                    else:
                        # Might be JSON error response
                        logger.warning(f"Unexpected content type: {content_type}")
                        return None
                elif response.status_code == 422:
                    # Validation error - try to get details
                    logger.error(f"Purple agent validation error: {response.text}")
                    return None
                else:
                    logger.error(f"Purple agent error: {response.status_code} - {response.text}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.error(f"Purple agent timeout after {self.timeout}s")
            return None
        except Exception as e:
            logger.error(f"Purple agent error: {e}")
            return None
    
    def _build_instructions(self, task_description: dict) -> str:
        """Build instructions string from task description"""
        parts = []
        
        if "description" in task_description:
            parts.append(f"Description: {task_description['description']}")
        
        if "vulnerability_type" in task_description:
            parts.append(f"Vulnerability Type: {task_description['vulnerability_type']}")
        
        if "target" in task_description:
            parts.append(f"Target: {task_description['target']}")
            
        if "hints" in task_description:
            parts.append(f"Hints: {task_description['hints']}")
        
        return "\n".join(parts) if parts else f"Generate PoC for {task_description.get('task_id', 'unknown task')}"


# ============================================================================
# Green Agent Implementation
# ============================================================================

class CyberGymGreenAgent:
    """
    Green Agent that evaluates Purple Agents on CyberGym tasks.
    
    Flow:
    1. Receive EvalRequest with Purple Agent endpoints
    2. For each task:
       a. Send task description to Purple Agent
       b. Receive PoC from Purple Agent
       c. Validate PoC using CyberGym server
       d. Record score
    3. Return final results
    """
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.adapter = CyberGymAdapter(server_url=self.config.CYBERGYM_SERVER_URL)
        self.task_loader = TaskDataLoader()
    
    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        """Validate incoming evaluation request"""
        if not request.participants:
            return False, "No participants provided"
        
        # Accept any participant - AgentBeats uses name from scenario.toml
        if len(request.participants) == 0:
            return False, "No participants in request"
        
        return True, "OK"
    
    async def run_eval(self, request: EvalRequest, updater=None) -> EvalResult:
        """
        Run the full evaluation.
        
        Args:
            request: EvalRequest with participant endpoints
            updater: Optional TaskUpdater for progress updates
            
        Returns:
            EvalResult with scores and details
        """
        # Get first participant endpoint (AgentBeats sends name from scenario.toml)
        purple_endpoint = None
        participant_name = None
        
        for name, endpoint in request.participants.items():
            purple_endpoint = str(endpoint)
            participant_name = name
            logger.info(f"Using participant: {name} -> {endpoint}")
            break
        
        if not purple_endpoint:
            return EvalResult(winner="none", detail={"error": "No participant endpoint found"})
        
        # Get task list from config or request
        task_ids = request.config.get("tasks", self.config.TASK_IDS)
        
        # Initialize client
        purple_client = PurpleAgentClient(
            endpoint=purple_endpoint,
            timeout=self.config.PURPLE_AGENT_TIMEOUT
        )
        
        # Track results
        results: list[TaskResult] = []
        total_score = 0
        successful_tasks = 0
        
        logger.info(f"Starting evaluation with {len(task_ids)} tasks")
        
        for i, task_id in enumerate(task_ids):
            logger.info(f"\n[{i+1}/{len(task_ids)}] Processing task: {task_id}")
            
            if updater:
                await updater.update_status(
                    "working",
                    f"Processing task {i+1}/{len(task_ids)}: {task_id}"
                )
            
            # Get task description
            task_desc = self.task_loader.get_task_description(task_id)
            
            # Request PoC from Purple Agent
            logger.info(f"  Requesting PoC from Purple Agent...")
            poc_data = await purple_client.request_poc(task_desc, f"eval-{task_id}")
            
            if poc_data is None:
                logger.warning(f"  No PoC received for {task_id}")
                results.append(TaskResult(
                    task_id=task_id,
                    success=False,
                    score=0,
                    exit_code=-1,
                    reason="No PoC received from Purple Agent"
                ))
                continue
            
            logger.info(f"  Received PoC: {len(poc_data)} bytes")
            
            # Validate PoC using CyberGym
            logger.info(f"  Validating with CyberGym server...")
            validation = self.adapter.validate_poc(
                task_id=task_id,
                poc_data=poc_data,
                agent_id=f"purple-{hash(purple_endpoint) % 10000}",
                timeout=self.config.VALIDATION_TIMEOUT
            )
            
            # Record result
            task_result = TaskResult(
                task_id=task_id,
                success=validation.vulnerability_confirmed,
                score=validation.score,
                exit_code=validation.exit_code,
                reason=validation.reason,
                poc_size=len(poc_data),
                poc_id=validation.poc_id
            )
            results.append(task_result)
            
            if validation.vulnerability_confirmed:
                successful_tasks += 1
                total_score += validation.score
                logger.info(f"  ✅ SUCCESS! Score: {validation.score}, Reason: {validation.reason}")
            else:
                logger.info(f"  ❌ Failed: {validation.reason}")
        
        # Calculate final score
        max_possible = len(task_ids) * 100
        final_score = (total_score / max_possible * 100) if max_possible > 0 else 0
        
        logger.info(f"\n{'='*50}")
        logger.info(f"Evaluation Complete!")
        logger.info(f"  Tasks: {successful_tasks}/{len(task_ids)} successful")
        logger.info(f"  Score: {total_score}/{max_possible} ({final_score:.1f}%)")
        logger.info(f"{'='*50}")
        
        # Build result
        return EvalResult(
            winner=participant_name if successful_tasks > 0 else "none",
            detail={
                "total_tasks": len(task_ids),
                "successful_tasks": successful_tasks,
                "total_score": total_score,
                "max_score": max_possible,
                "percentage": round(final_score, 2),
                "task_results": [asdict(r) for r in results]
            }
        )


# ============================================================================
# A2A Server Integration
# ============================================================================

# Global variable to store the card_url for Agent Card generation
AGENT_CARD_URL = ""

def create_green_agent_server(config: Config = None, card_url: str = ""):
    """
    Create a FastAPI server for the Green Agent.
    
    This integrates with AgentBeats A2A protocol.
    """
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    
    app = FastAPI(title="CyberGym Green Agent")
    agent = CyberGymGreenAgent(config)
    
    # Store card_url in app state
    app.state.card_url = card_url
    
    @app.get("/")
    async def root():
        return {"status": "CyberGym Green Agent Running"}
    
    @app.get("/.well-known/agent-card.json")
    async def agent_card():
        """Return A2A Agent Card - MUST follow A2A specification"""
        return {
            "name": "CyberGym Green Agent",
            "description": "Evaluates AI agents on cybersecurity vulnerability exploitation tasks",
            "version": "1.0.0",
            "url": app.state.card_url or AGENT_CARD_URL,
            "capabilities": {
                "streaming": False,
                "pushNotifications": False
            },
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text"],
            "skills": [
                {
                    "id": "cybergym-assessment",
                    "name": "CyberGym Assessment",
                    "description": "Evaluates Purple Agents on vulnerability exploitation tasks",
                    "tags": ["assessment", "cybergym", "security"]
                }
            ]
        }
    
    @app.post("/a2a")
    async def a2a_endpoint(request: Request):
        """Handle A2A JSON-RPC requests"""
        try:
            body = await request.json()
            method = body.get("method", "")
            params = body.get("params", {})
            req_id = body.get("id", "1")
            
            # Log incoming request for debugging
            logger.info(f"A2A Request - Method: {method}")
            logger.info(f"A2A Params: {json.dumps(params, indent=2)[:500]}")
            
            if method == "message/send":
                message = params.get("message", {})
                incoming_context_id = message.get("contextId", str(uuid.uuid4()))
                
                # Try multiple ways to find text content
                text_content = None
                
                # Method 1: parts array with kind=text (A2A format)
                parts = message.get("parts", [])
                for part in parts:
                    if isinstance(part, dict):
                        # A2A uses "kind" not "type"
                        if part.get("kind") == "text" or part.get("type") == "text":
                            text_content = part.get("text", "")
                            break
                
                # Method 2: Direct text field
                if not text_content:
                    text_content = message.get("text", "")
                
                # Method 3: Content field
                if not text_content:
                    content = message.get("content", {})
                    if isinstance(content, str):
                        text_content = content
                    elif isinstance(content, dict):
                        text_content = content.get("text", "")
                
                # Method 4: First part as string
                if not text_content and parts:
                    first_part = parts[0]
                    if isinstance(first_part, str):
                        text_content = first_part
                    elif isinstance(first_part, dict):
                        text_content = first_part.get("text", "") or first_part.get("data", "")
                
                # Method 5: Raw params text
                if not text_content:
                    text_content = params.get("text", "")
                
                logger.info(f"Extracted text content: {text_content[:200] if text_content else 'NONE'}...")
                
                if not text_content:
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602, 
                            "message": f"No text found. Message structure: {json.dumps(message)[:500]}"
                        }
                    })
                
                try:
                    eval_req = EvalRequest.model_validate_json(text_content)
                    ok, msg = agent.validate_request(eval_req)
                    if not ok:
                        return JSONResponse({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32602, "message": msg}
                        })
                    
                    # Run evaluation
                    result = await agent.run_eval(eval_req)
                    
                    # Return A2A-compliant response
                    # The result should be a Message object with all required fields
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "kind": "message",
                            "messageId": str(uuid.uuid4()),
                            "role": "agent",
                            "parts": [
                                {"kind": "text", "text": result.model_dump_json()}
                            ],
                            "contextId": incoming_context_id
                        }
                    })
                except Exception as e:
                    logger.error(f"Evaluation error: {e}")
                    import traceback
                    traceback.print_exc()
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32603, "message": str(e)}
                    })
            
            # Unknown method
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"}
            })
            
        except Exception as e:
            logger.error(f"A2A endpoint error: {e}")
            import traceback
            traceback.print_exc()
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": "1",
                "error": {"code": -32700, "message": str(e)}
            })
    
    # POST to root calls a2a_endpoint (must be defined AFTER a2a_endpoint)
    @app.post("/")
    async def root_post(request: Request):
        """Handle A2A JSON-RPC requests at root"""
        return await a2a_endpoint(request)
    
    return app


# ============================================================================
# Main Entry Point
# ============================================================================

def parse_args():
    """Parse command line arguments - AgentBeats compatible"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberGym Green Agent")
    
    # Standard AgentBeats arguments (REQUIRED for A2A protocol)
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"), 
                        help="Host to bind to")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")), 
                        help="Port to listen on")
    parser.add_argument("--card-url", default=os.getenv("CARD_URL", ""), 
                        help="Public URL for the Agent Card")
    
    # Additional arguments
    parser.add_argument("--cybergym-url", default=os.getenv("CYBERGYM_SERVER_URL", "http://localhost:8666"), 
                        help="CyberGym server URL")
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Store card_url globally for Agent Card generation
    AGENT_CARD_URL = args.card_url
    
    # Create config
    config = Config(CYBERGYM_SERVER_URL=args.cybergym_url)
    
    # Print startup info
    print("=" * 60)
    print("CyberGym Green Agent")
    print("=" * 60)
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Card URL: {args.card_url or '(not set)'}")
    print(f"CyberGym Server: {config.CYBERGYM_SERVER_URL}")
    print("=" * 60)
    
    # Create and run server
    import uvicorn
    app = create_green_agent_server(config, card_url=args.card_url)
    uvicorn.run(app, host=args.host, port=args.port)
