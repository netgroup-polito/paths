#!/bin/bash
set -e

echo "PATHS - Starting"
echo "==================================="
echo ""

# Check if running in Docker
if [ -f "/.dockerenv" ]; then
    echo "Running in Docker container"
    echo ""
    python app.py
else
    # Local execution
    if ! command -v python3 &> /dev/null; then
        echo "Python 3 is not installed"
        exit 1
    fi

    echo "✓ Python 3 found: $(python3 --version)"
    echo ""

    # Create virtual environment if needed
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi

    echo "Activating virtual environment..."
    source venv/bin/activate

    echo "Installing dependencies..."
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    pip install -q -r requirements.txt

    echo "✓ Dependencies installed"
    echo ""
    echo "Starting application..."
    echo "📱 Server available at: http://localhost:5001"
    echo "📱 Press Ctrl+C to stop"
    echo ""

    python app.py
fi
