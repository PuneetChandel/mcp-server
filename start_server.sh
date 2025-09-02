#!/bin/bash

# Script to start Billing MCP Server in HTTP mode
# Usage: ./start_server.sh

# Read port from .env file
if [ -f ".env" ]; then
    # Source the .env file to get SERVER_PORT
    export $(grep -v '^#' .env | xargs)
    PORT=${SERVER_PORT:-8000}
    echo "Using port $PORT from .env file"
else
    echo "Error: .env file not found. Please create one with your billing system credentials."
    exit 1
fi

echo "Starting Billing MCP Server..."
echo "Port: $PORT"
echo "Working directory: $(pwd)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found. Please create one first."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if required environment variables are set
if [ -z "$BILLING_BASE_URL" ] || [ -z "$BILLING_CLIENT_ID" ] || [ -z "$BILLING_CLIENT_SECRET" ]; then
    echo "Warning: Required billing system environment variables not found in .env file."
    echo "Required variables: BILLING_BASE_URL, BILLING_CLIENT_ID, BILLING_CLIENT_SECRET"
fi

# Start the server
echo "Starting Billing MCP Server on port $PORT..."
echo "Press Ctrl+C to stop the server"
./venv/bin/python main.py --http --port $PORT
