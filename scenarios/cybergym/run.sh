#!/bin/bash
# CyberGym Docker System - Run Script
# Starts all services for Phase 1 submission
#
# FIRST TIME SETUP: Make this script executable:
#   chmod +x run.sh
#
# USAGE:
#   ./run.sh all      - Start all services
#   ./run.sh stop     - Stop all services
#   ./run.sh status   - Check service status
#   ./run.sh test     - Run test suite

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       CyberGym Docker System - Startup Script              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file not found${NC}"
    echo "Creating from sample.env..."
    cp sample.env .env
    echo -e "${YELLOW}Please edit .env and add your GOOGLE_API_KEY${NC}"
fi

# Check Docker
echo -e "\n${BLUE}Checking Docker...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    echo "Please start Docker Desktop and try again"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Check Docker images
echo -e "\n${BLUE}Checking Docker images...${NC}"
IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep "cybergym/" || true)
if [ -z "$IMAGES" ]; then
    echo -e "${YELLOW}No CyberGym images found${NC}"
    echo "Building Docker images..."
    python docker_setup.py --build
else
    COUNT=$(echo "$IMAGES" | wc -l)
    echo -e "${GREEN}✓ Found $COUNT CyberGym images${NC}"
fi

# Function to start a service in background
start_service() {
    local name=$1
    local cmd=$2
    local port=$3
    
    echo -e "\n${BLUE}Starting $name on port $port...${NC}"
    
    # Check if port is already in use
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}Port $port already in use - $name may already be running${NC}"
        return 0
    fi
    
    # Start in background
    $cmd > logs/${name}.log 2>&1 &
    local pid=$!
    echo $pid > logs/${name}.pid
    
    # Wait for service to start
    sleep 2
    
    if kill -0 $pid 2>/dev/null; then
        echo -e "${GREEN}✓ $name started (PID: $pid)${NC}"
    else
        echo -e "${RED}✗ $name failed to start${NC}"
        echo "Check logs/${name}.log for details"
        return 1
    fi
}

# Create logs directory
mkdir -p logs

# Parse command line arguments
case "${1:-all}" in
    validator)
        start_service "validator" "python docker_validator.py" 8666
        ;;
    green)
        start_service "green_agent" "python green_agent_prod.py" 9030
        ;;
    purple)
        start_service "purple_agent" "python purple_agent_prod.py" 9031
        ;;
    all)
        start_service "validator" "python docker_validator.py" 8666
        sleep 2
        start_service "green_agent" "python green_agent_prod.py" 9030
        sleep 2
        start_service "purple_agent" "python purple_agent_prod.py" 9031
        ;;
    stop)
        echo -e "\n${BLUE}Stopping services...${NC}"
        for pidfile in logs/*.pid; do
            if [ -f "$pidfile" ]; then
                pid=$(cat $pidfile)
                name=$(basename $pidfile .pid)
                if kill -0 $pid 2>/dev/null; then
                    kill $pid
                    echo -e "${GREEN}✓ Stopped $name (PID: $pid)${NC}"
                fi
                rm -f $pidfile
            fi
        done
        echo -e "${GREEN}All services stopped${NC}"
        exit 0
        ;;
    status)
        echo -e "\n${BLUE}Service Status:${NC}"
        
        # Check validator
        if curl -s http://localhost:8666/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Validator: Running${NC}"
        else
            echo -e "${RED}✗ Validator: Not running${NC}"
        fi
        
        # Check green agent
        if curl -s http://localhost:9030/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Green Agent: Running${NC}"
        else
            echo -e "${RED}✗ Green Agent: Not running${NC}"
        fi
        
        # Check purple agent
        if curl -s http://localhost:9031/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Purple Agent: Running${NC}"
        else
            echo -e "${RED}✗ Purple Agent: Not running${NC}"
        fi
        exit 0
        ;;
    test)
        echo -e "\n${BLUE}Running tests...${NC}"
        python test_docker_system.py
        exit $?
        ;;
    *)
        echo "Usage: $0 {all|validator|green|purple|stop|status|test}"
        echo ""
        echo "Commands:"
        echo "  all       Start all services (default)"
        echo "  validator Start only the Docker validator"
        echo "  green     Start only the Green Agent"
        echo "  purple    Start only the Purple Agent"
        echo "  stop      Stop all services"
        echo "  status    Check service status"
        echo "  test      Run test suite"
        exit 1
        ;;
esac

# Final status
echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Services started! Endpoints:${NC}"
echo "  Validator:    http://localhost:8666"
echo "  Green Agent:  http://localhost:9030"
echo "  Purple Agent: http://localhost:9031"
echo ""
echo "Logs available in: ./logs/"
echo ""
echo "To stop all services: $0 stop"
echo "To check status:      $0 status"
echo "To run tests:         $0 test"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"