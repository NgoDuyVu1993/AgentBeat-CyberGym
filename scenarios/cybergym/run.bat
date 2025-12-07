@echo off
REM CyberGym Docker System - Run Script for Windows
REM Starts all services for Phase 1 submission

echo.
echo ============================================================
echo         CyberGym Docker System - Startup Script
echo ============================================================
echo.

REM Check for .env file
if not exist ".env" (
    echo Warning: .env file not found
    echo Creating from sample.env...
    copy sample.env .env
    echo Please edit .env and add your GOOGLE_API_KEY
    echo.
)

REM Check Docker
echo Checking Docker...
docker info >nul 2>&1
if errorlevel 1 (
    echo Error: Docker is not running
    echo Please start Docker Desktop and try again
    exit /b 1
)
echo [OK] Docker is running

REM Create logs directory
if not exist "logs" mkdir logs

REM Parse arguments
if "%1"=="" goto :all
if "%1"=="all" goto :all
if "%1"=="validator" goto :validator
if "%1"=="green" goto :green
if "%1"=="purple" goto :purple
if "%1"=="test" goto :test
if "%1"=="status" goto :status
goto :usage

:all
echo.
echo Starting all services...
echo.

echo Starting Validator on port 8666...
start "CyberGym Validator" /min cmd /c "python docker_validator.py > logs\validator.log 2>&1"
timeout /t 3 /nobreak >nul

echo Starting Green Agent on port 9030...
start "CyberGym Green Agent" /min cmd /c "python green_agent_prod.py > logs\green_agent.log 2>&1"
timeout /t 2 /nobreak >nul

echo Starting Purple Agent on port 9031...
start "CyberGym Purple Agent" /min cmd /c "python purple_agent_prod.py > logs\purple_agent.log 2>&1"
timeout /t 2 /nobreak >nul

goto :done

:validator
echo Starting Validator on port 8666...
start "CyberGym Validator" cmd /c "python docker_validator.py"
goto :done

:green
echo Starting Green Agent on port 9030...
start "CyberGym Green Agent" cmd /c "python green_agent_prod.py"
goto :done

:purple
echo Starting Purple Agent on port 9031...
start "CyberGym Purple Agent" cmd /c "python purple_agent_prod.py"
goto :done

:test
echo Running tests...
python test_docker_system.py
goto :end

:status
echo.
echo Service Status:
echo.

curl -s http://localhost:8666/health >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Validator: Not running
) else (
    echo [OK] Validator: Running
)

curl -s http://localhost:9030/health >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Green Agent: Not running
) else (
    echo [OK] Green Agent: Running
)

curl -s http://localhost:9031/health >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Purple Agent: Not running
) else (
    echo [OK] Purple Agent: Running
)
goto :end

:done
echo.
echo ============================================================
echo Services started! Endpoints:
echo   Validator:    http://localhost:8666
echo   Green Agent:  http://localhost:9030
echo   Purple Agent: http://localhost:9031
echo.
echo Logs available in: .\logs\
echo.
echo To check status: run.bat status
echo To run tests:    run.bat test
echo ============================================================
goto :end

:usage
echo Usage: run.bat [command]
echo.
echo Commands:
echo   all       Start all services (default)
echo   validator Start only the Docker validator
echo   green     Start only the Green Agent
echo   purple    Start only the Purple Agent
echo   status    Check service status
echo   test      Run test suite
echo.

:end
