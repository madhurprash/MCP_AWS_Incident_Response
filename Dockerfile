FROM python:3.12-slim

WORKDIR /app

# Install astral uv for Python dependencies
RUN pip install uv

# Copy project files
COPY pyproject.toml .
COPY globals.py .
COPY server_scripts/ server_scripts/

# Install dependencies using uv
RUN uv pip install --no-cache --system -e .

# Add AWS configuration directory
RUN mkdir -p /root/.aws

# Environment variables will be passed at runtime
ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""
ENV AWS_REGION="us-east-1"
ENV JIRA_API_TOKEN=""
ENV JIRA_USERNAME=""
ENV JIRA_INSTANCE_URL=""
ENV JIRA_CLOUD="True"
ENV PROJECT_KEY="ASCRT"
ENV BEDROCK_LOG_GROUP="bedrockloggroup"
ENV MCP_TRANSPORT="stdio"

# Expose port for SSE transport (if needed later)
EXPOSE 8000

# Entry point with selectable server script
ENTRYPOINT ["python"]
