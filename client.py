import os
import sys
import json
import asyncio
from globals import *
from contextlib import AsyncExitStack
from langchain_aws import ChatBedrock
from typing import Optional, Dict, List
from mcp.client.stdio import stdio_client
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from langchain_mcp_adapters.client import MultiServerMCPClient

class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.tools = None
        self.system_prompt = None
        
    async def connect_to_server(self):
        """Connect to an MCP server"""
        server_params = StdioServerParameters(
            command="python",
            args=[MONTITORING_SCRIPT_PATH]
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        # initialize the MCP server
        await self.session.initialize()
        print(f"Connected to the AWS MCP Incident server")
        
        try:
            # Get the prompt response
            self.prompt_response = await self.session.get_prompt("analyze_aws_logs")
            
            # Extract the text directly from the structure we can see in the output
            if hasattr(self.prompt_response, 'messages') and self.prompt_response.messages:
                # Access the text field directly from the content object
                self.system_prompt = self.prompt_response.messages[0].content.text
                print(f"System prompt: {self.system_prompt}")
            else:
                # Fallback if structure is different
                self.system_prompt = """
                You are the monitoring agent responsible for analyzing CloudWatch logs for AWS services.
                """
        except Exception as e:
            print(f"Error extracting prompt: {e}")
            raise e
            
        # List available tools
        self.tools = await load_mcp_tools(self.session)
        print("Available tools:", [tool.name for tool in self.tools])
        
        # List available resources
        try:
            resources_response = await self.session.list_resources()
            self.resources = resources_response.resources
            print("Available resources:", [resource.uri for resource in self.resources])
        except Exception as e:
            print(f"No resources available or error listing resources: {e}")
            self.resources = []

    async def process_query(self, query: str) -> str:
        """Process a query using ReAct agent and available tools"""
        if not self.session:
            return "Error: Not connected to server. Please connect first."
        
        if not self.system_prompt:
            return "Error: System prompt not available."
        
        try:
            # Create a model instance
            model = ChatBedrock(model_id=CLAUDE_3_5_HAIKU)
            
            # Create a ReAct agent using the adapter itself
            agent = create_react_agent(
                model,
                self.tools
            )
            print(f"Initialized the AWS Incident REACT agent...")
            formatted_messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": query}
            ]
            print(f"Formatted messages: {formatted_messages}")
            response = await agent.ainvoke({"messages": formatted_messages})
            print(f"Response: {response}")
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