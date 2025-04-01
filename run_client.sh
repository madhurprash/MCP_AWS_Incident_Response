#!/bin/bash

# Export Jira environment variables
export JIRA_API_TOKEN="ATATT3xFfGF0fTdCZhMeyw_cY8kmWVn0mhJ5yaRfIMLrLd2YNbrLE6mgl6tvr_P_FNZZxcvcby2EfGDI3uJjgzU0fC-s5Ux8m53wPA4SwFMu7WXdtNyUDba_gAPVFRKkIRUEShxGxGn4S5iTTzh32E6y0QHdASYf1gjJ278CubeV5yJfXUPcdf8=A73BFA07" 
export JIRA_USERNAME="madhurprashant7" 
export JIRA_INSTANCE_URL="https://madhurprashant7.atlassian.net/" 
export JIRA_CLOUD="True" 
export PROJECT_KEY="ASCRT"

echo "Jira environment variables exported successfully"

# Get the path to the Python executable being used
PYTHON_PATH=$(which python)
echo "Using Python executable: $PYTHON_PATH"

# Run the client script with the explicit Python path
uv run client.py --python-path "$PYTHON_PATH"