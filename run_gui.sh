#!/bin/bash
# Launch script for Secure Messenger GUI
# ICS344 - Group P26

echo "=================================================="
echo "    SECURE MESSENGER GUI - ICS344 GROUP P26"
echo "=================================================="
echo ""

# Change to script directory
cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv311" ]; then
    echo "Creating Python 3.11 virtual environment..."
    python3.11 -m venv venv311
    source venv311/bin/activate
    pip install --upgrade pip
    pip install cryptography==41.0.7
    pip install "kivy[base]"
else
    echo "✓ Using existing virtual environment"
    source venv311/bin/activate
fi

echo "✓ Python version: $(python --version)"
echo "✓ Kivy installed: $(pip show kivy | grep Version)"
echo ""
echo "Starting GUI application..."
echo ""

# Run the enhanced GUI
python main_enhanced.py

# Deactivate when done
deactivate