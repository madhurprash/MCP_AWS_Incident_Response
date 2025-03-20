# client.py
import os
import asyncio
from typing import Optional, Dict, List
from contextlib import AsyncExitStack
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_aws import ChatBedrock
import sys
import json

from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters


# Global variables
CLAUDE_3_5_SONNET: str = 'us.anthropic.claude-3-sonnet-20240229-v1:0'

prompt_response: str = """You are the monitoring agent responsible for analyzing CloudWatch logs for AWS services.
    Your tasks include:
    1. Fetch recent CloudWatch logs for the requested service.
    2. Identify any errors, warnings, or anomalies in the logs.
    3. Look for patterns or recurring issues.
    4. Provide a summary of log findings and any potential actions needed.
    5. Report your findings to the user in a clear, organized manner.
    
    First, you may need to list available services to help the user choose which service logs to analyze.
    Then, fetch and analyze the logs for their chosen service for the specified time period.
    Be thorough in your investigation but concise in your reporting.
    
    Always fetch the cloudwatch logs on a certain service, then get the logs and then fetch 
    any relevant alarms.
        """

class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.tools = None
        
    async def connect_to_server(self):
        """Connect to an MCP server
        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        server_params = StdioServerParameters(
            command="python",
            args=["monitoring_agent_server.py"]
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        # initialize the MCP server
        await self.session.initialize()
        print(f"Connected to the AWS MCP Incident server")
        # Here, we can fetch the session and then get the prompt within the "analyze_aws_logs" prompt tool
        # within the server. This can help us abstract out the prompts and use pre built prompts within the MCP
        # server that will be used by default when the user asks a question
        self.prompt_response = await self.session.get_prompt("analyze_aws_logs")

        # List available tools
        self.tools = await load_mcp_tools(self.session)
        print("Available tools:", [tool.name for tool in self.tools])
        
        # List available resources
        try:
            resources_response = await self.session.list_resources()
            self.resources = resources_response.resources
            # Show the available resources that the user can ask questions on and get cloudwatch logs, 
            # and then analyze problems, diagnose it and then create JIRA tickets to resolve the issues
            print("Available resources:", [resource.uri for resource in self.resources])
        except Exception as e:
            print(f"No resources available or error listing resources: {e}")
            self.resources = []

    async def process_query(self, query: str) -> str:
        """Process a query using ReAct agent and available tools"""
        if not self.session:
            return "Error: Not connected to server. Please connect first."
        
        try:
            # Create a model instance
            model = ChatBedrock(model_id=CLAUDE_3_5_SONNET)
            # Create a ReAct agent using the adapter itself
            agent = create_react_agent(
                model,
                # These are the tools that the monitoring agent has
                # access to, which includes the fetch cloudwatch
                # logs, list services and then fetch if there are any
                # alarms in your AWS account
                self.tools
            )
            print(f"Initialized the AWS Incident REACT agent...")
            # Invoke the agent
            formatted_messages = [
                {"role": "system", "content": prompt_response},
                {"role": "user", "content": query}
            ]
            response = await agent.ainvoke({"messages": formatted_messages})
            
            # Process the response
            if response and "messages" in response and response["messages"]:
                last_message = response["messages"][-1]
                if isinstance(last_message, dict) and "content" in last_message:
                    return last_message["content"]
                else:
                    return str(last_message.content)
            else:
                return "No valid response received"
                
        except Exception as e:
            print(f"Error details: {e}")
            import traceback
            traceback.print_exc()
            return f"Error processing query: {str(e)}"

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nAWS Incident Response Client Started!")
        print("Type your queries or 'quit' to exit.")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == 'quit':
                    break

                response = await self.process_query(query)
                print("\n" + response)

            except Exception as e:
                print(f"\nError: {str(e)}")

    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()

async def main():
    client = MCPClient()
    try:
        await client.connect_to_server()
        await client.chat_loop()
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
