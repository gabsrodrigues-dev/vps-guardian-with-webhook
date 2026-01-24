#!/bin/bash
# VPS Guardian - Test Runner Script
# Automatically detects and uses pytest or provides installation instructions

set -e

echo "VPS Guardian Test Suite Runner"
echo "==============================="
echo ""

# Check if pytest is available
if python3 -c "import pytest" 2>/dev/null; then
    echo "✅ pytest found"
    echo ""

    # Run tests
    if [ "$1" = "--cov" ]; then
        echo "Running tests with coverage..."
        python3 -m pytest tests/ --cov=guardian --cov-report=term-missing --cov-report=html -v
    elif [ "$1" = "--verbose" ]; then
        echo "Running tests in verbose mode..."
        python3 -m pytest tests/ -vv --tb=long
    else
        echo "Running tests..."
        python3 -m pytest tests/ -v --tb=short
    fi

else
    echo "❌ pytest not found"
    echo ""
    echo "Installation options:"
    echo ""
    echo "1. System packages (recommended):"
    echo "   sudo apt install python3-pytest python3-pytest-mock python3-pytest-cov"
    echo ""
    echo "2. Virtual environment:"
    echo "   sudo apt install python3-venv"
    echo "   python3 -m venv .venv"
    echo "   source .venv/bin/activate"
    echo "   pip install -r requirements-dev.txt"
    echo ""
    echo "3. User install (not recommended):"
    echo "   pip install --user pytest pytest-mock pytest-cov"
    echo ""
    exit 1
fi
