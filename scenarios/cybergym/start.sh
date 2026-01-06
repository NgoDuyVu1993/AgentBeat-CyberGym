#!/bin/bash
# start.sh - CyberGym Green Agent Startup Script (Phase 1 with Mock Fallback)
#
# This script:
# 1. Attempts to start CyberGym server (for real validation)
# 2. Starts Green Agent regardless of server status
# 3. Green Agent will use mock fallback if server fails (Docker-in-Docker limitation)

echo "============================================================"
echo "🚀 Starting CyberGym Green Agent (Surgical Build v3 - Phase 1)"
echo "============================================================"

# Configuration
PORT=8666
POC_SAVE_DIR=/app/server_poc
CYBERGYM_SERVER_DATA_DIR=/app/cybergym_data/oss-fuzz-data

# Verify CyberGym installation
echo "📋 Verifying CyberGym installation..."

# Check if cybergym.server module exists
if python3 -c "import cybergym.server" 2>/dev/null; then
    echo "✅ CyberGym server module found via import"
    SERVER_MODULE_FOUND=true
else
    echo "⚠️ CyberGym server module NOT found via import"
    echo "   Checking if module can run..."
    
    if python3 -m cybergym.server --help 2>/dev/null | head -1; then
        echo "✅ CyberGym server module available via -m"
        SERVER_MODULE_FOUND=true
    else
        echo "❌ CyberGym server module not available"
        SERVER_MODULE_FOUND=false
    fi
fi

# Check if surgical data exists
if [ -d "$CYBERGYM_SERVER_DATA_DIR" ]; then
    echo "📦 Found surgical data, starting CyberGym Validator Server..."
    echo "Available task data:"
    ls -la "$CYBERGYM_SERVER_DATA_DIR"
    
    if [ "$SERVER_MODULE_FOUND" = true ]; then
        # Create POC save directory
        mkdir -p "$POC_SAVE_DIR"
        
        echo "🔄 Starting CyberGym server on port $PORT..."
        
        # Start CyberGym server in background
        # Note: This will fail when trying to run Docker containers, but we try anyway
        # The Green Agent's mock fallback will handle HTTP 500 errors
        python3 -m cybergym.server \
            --host 127.0.0.1 \
            --port $PORT \
            --log_dir $POC_SAVE_DIR \
            --db_path $POC_SAVE_DIR/poc.db \
            --cybergym_oss_fuzz_path $CYBERGYM_SERVER_DATA_DIR &
        
        SERVER_PID=$!
        
        # Wait for server to initialize
        sleep 5
        
        # Check if server process is still running
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo "✅ CyberGym server process started (PID: $SERVER_PID)"
            
            # Wait for server to be ready
            echo "⏳ Waiting for CyberGym server to be healthy..."
            for i in {1..30}; do
                if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/" | grep -q "404\|200"; then
                    echo "✅ CyberGym Validator Server is HEALTHY on http://127.0.0.1:$PORT"
                    break
                fi
                
                if [ $i -eq 30 ]; then
                    echo "⚠️ CyberGym server health check timed out, but continuing anyway"
                    echo "   Mock fallback will handle validation failures"
                fi
                
                sleep 2
            done
        else
            echo "⚠️ CyberGym server process failed to start"
            echo "   Mock fallback will handle all validations"
        fi
    else
        echo "⚠️ CyberGym server module not available"
        echo "   Mock fallback will handle all validations"
    fi
else
    echo "⚠️ No surgical data found at $CYBERGYM_SERVER_DATA_DIR"
    echo "   Mock fallback will handle all validations"
fi

# Start the Green Agent
echo "============================================================"
echo "🟢 Starting Green Agent on port 8080..."
echo "============================================================"

# The Green Agent will:
# 1. Try real validation with CyberGym server
# 2. Fall back to mock validation if server returns HTTP 500 (Docker-in-Docker issue)
# 3. Be transparent in 'reason' field about validation mode

python cybergym_green_agent.py "$@"

# Cleanup
if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
    echo "🛑 Shutting down CyberGym server..."
    kill $SERVER_PID 2>/dev/null
fi
