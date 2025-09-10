#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "Checking for virtual environment..."

# Check if the .venv directory exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment. Please ensure python3 and venv are installed."
        exit 1
    fi
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source ./.venv/bin/activate

# Install/update requirements
echo "Installing/updating requirements..."
pip install -r requirements.txt

# Run the Python application
echo "Starting the Python application with arguments: $@"
python3 -m gemini_cli_openaiapi_proxy "$@"

echo "Application has finished."
