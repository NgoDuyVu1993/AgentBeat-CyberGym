#!/bin/bash
# start.sh - CyberGym Green Agent Startup Script (Phase 1 with Mock Fallback)

echo "============================================================"
echo "🚀 Starting CyberGym Green Agent (Surgical Build v3 - Phase 1)"
echo "============================================================"

# Configuration - USE DIFFERENT PORTS!
CYBERGYM_PORT=8666          # Internal CyberGym validator
GREEN_AGENT_PORT=9009       # External Green Agent (matches Dockerfile EXPOSE)
POC_SAVE_DIR=/app/server_poc
CYBERGYM_SERVER_DATA_DIR=/app/cybergym_data/oss-fuzz-data

# Verify CyberGym installation
echo "📋 Verifying CyberGym installation..."

if python3 -c "import cybergym.server" 2>/dev/null; then
    echo "✅ CyberGym server module found via import"
    SERVER_MODULE_FOUND=true
else
    echo "⚠️ CyberGym server module NOT found via import"
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
        mkdir -p "$POC_SAVE_DIR"
        
        echo "🔄 Starting CyberGym server on port $CYBERGYM_PORT..."
        
        python3 -m cybergym.server \
            --host 127.0.0.1 \
            --port $CYBERGYM_PORT \
            --log_dir $POC_SAVE_DIR \
            --db_path $POC_SAVE_DIR/poc.db \
            --cybergym_oss_fuzz_path $CYBERGYM_SERVER_DATA_DIR &
        
        SERVER_PID=$!
        sleep 5
        
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo "✅ CyberGym server process started (PID: $SERVER_PID)"
            
            echo "⏳ Waiting for CyberGym server to be healthy..."
            for i in {1..30}; do
                if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$CYBERGYM_PORT/" | grep -q "404\|200"; then
                    echo "✅ CyberGym Validator Server is HEALTHY on http://127.0.0.1:$CYBERGYM_PORT"
                    break
                fi
                
                if [ $i -eq 30 ]; then
                    echo "⚠️ CyberGym server health check timed out, but continuing anyway"
                fi
                
                sleep 2
            done
        else
            echo "⚠️ CyberGym server process failed to start"
        fi
    fi
else
    echo "⚠️ No surgical data found at $CYBERGYM_SERVER_DATA_DIR"
fi

# Start the Green Agent on port 9009
echo "============================================================"
echo "🟢 Starting Green Agent on port $GREEN_AGENT_PORT..."
echo "============================================================"

# Export the correct port for the Green Agent
export PORT=$GREEN_AGENT_PORT
export HOST=0.0.0.0
export CYBERGYM_SERVER_URL=http://127.0.0.1:$CYBERGYM_PORT

python cybergym_green_agent.py "$@"

# Cleanup
if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
    echo "🛑 Shutting down CyberGym server..."
    kill $SERVER_PID 2>/dev/null
fi