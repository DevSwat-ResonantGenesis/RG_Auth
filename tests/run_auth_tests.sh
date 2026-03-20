#!/bin/bash
# Auth Service Integration Test Runner
# Author: Agent 7 - ResonantGenesis Team
# Created: February 21, 2026

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=========================================="
echo "ResonantGenesis Auth Service Tests"
echo "=========================================="
echo ""

# Set test environment
export TESTING=true
export PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/auth_service:$PYTHONPATH"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo "Installing pytest..."
    pip install pytest pytest-asyncio httpx
fi

# Run tests with different options
case "${1:-default}" in
    "unit"|"-u")
        echo "Running unit tests only..."
        pytest "$SCRIPT_DIR/test_auth.py" -v --tb=short
        ;;
    "integration"|"-i")
        echo "Running integration tests only..."
        pytest "$SCRIPT_DIR/test_auth_integration.py" -v --tb=short
        ;;
    "verbose"|"-v")
        echo "Running all tests in verbose mode..."
        pytest "$SCRIPT_DIR" -v --tb=long
        ;;
    "quiet"|"-q")
        echo "Running all tests in quiet mode..."
        pytest "$SCRIPT_DIR" -q
        ;;
    "coverage"|"-c")
        echo "Running tests with coverage..."
        pip install pytest-cov 2>/dev/null || true
        pytest "$SCRIPT_DIR" -v --cov=app --cov-report=term-missing
        ;;
    "login")
        echo "Running login tests only..."
        pytest "$SCRIPT_DIR" -v -k "Login or login"
        ;;
    "registration")
        echo "Running registration tests only..."
        pytest "$SCRIPT_DIR" -v -k "Registration or Register or register"
        ;;
    "oauth")
        echo "Running OAuth tests only..."
        pytest "$SCRIPT_DIR" -v -k "OAuth or oauth or SSO"
        ;;
    "mfa")
        echo "Running MFA tests only..."
        pytest "$SCRIPT_DIR" -v -k "MFA or mfa"
        ;;
    "api-keys")
        echo "Running API key tests only..."
        pytest "$SCRIPT_DIR" -v -k "APIKey or api_key or ApiKey"
        ;;
    *)
        echo "Running all tests..."
        pytest "$SCRIPT_DIR" -v --tb=short
        ;;
esac

echo ""
echo "=========================================="
echo "Auth tests completed!"
echo "=========================================="
