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
        self.monitoring_session: Optional[ClientSession] = None
        self.jira_session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.monitoring_tools = None
        self.jira_tools = None
        self.monitoring_system_prompt = None
        self.jira_system_prompt = None
        
    async def connect_to_servers(self):
        """Connect to both MCP servers"""
        # Connect to monitoring server
        monitoring_params = StdioServerParameters(
            command="python",
            args=[MONTITORING_SCRIPT_PATH]
        )

        monitoring_transport = await self.exit_stack.enter_async_context(stdio_client(monitoring_params))
        monitoring_stdio, monitoring_write = monitoring_transport
        self.monitoring_session = await self.exit_stack.enter_async_context(
            ClientSession(monitoring_stdio, monitoring_write)
        )

        # Initialize the monitoring MCP server
        await self.monitoring_session.initialize()
        print(f"Connected to the AWS Monitoring server")
        
        # Connect to Jira server
        jira_params = StdioServerParameters(
            command="python",
            args=[DIAGNOSIS_SCRIPT_PATH]
        )

        jira_transport = await self.exit_stack.enter_async_context(stdio_client(jira_params))
        jira_stdio, jira_write = jira_transport
        self.jira_session = await self.exit_stack.enter_async_context(
            ClientSession(jira_stdio, jira_write)
        )

        # Initialize the Jira MCP server
        await self.jira_session.initialize()
        print(f"Connected to the AWS Jira Tickets server")
        
        # Get prompts from both servers
        try:
            # Get monitoring prompt
            self.monitoring_prompt_response = await self.monitoring_session.get_prompt("analyze_aws_logs")
            
            if hasattr(self.monitoring_prompt_response, 'messages') and self.monitoring_prompt_response.messages:
                self.monitoring_system_prompt = self.monitoring_prompt_response.messages[0].content.text
                print(f"Monitoring system prompt loaded")
            else:
                self.monitoring_system_prompt = """
                You are the monitoring agent responsible for analyzing CloudWatch logs for AWS services.
                """
                
            # Get Jira prompt
            self.jira_prompt_response = await self.jira_session.get_prompt("create_aws_jira_tickets")
            
            if hasattr(self.jira_prompt_response, 'messages') and self.jira_prompt_response.messages:
                self.jira_system_prompt = self.jira_prompt_response.messages[0].content.text
                print(f"Jira system prompt loaded")
            else:
                self.jira_system_prompt = """
                You are the AWS Jira Ticket Creation Agent.
                """
        except Exception as e:
            print(f"Error extracting prompts: {e}")
            raise e
            
        # Load tools from both servers
        self.monitoring_tools = await load_mcp_tools(self.monitoring_session)
        self.jira_tools = await load_mcp_tools(self.jira_session)
        
        # Combine all tools
        self.all_tools = self.monitoring_tools + self.jira_tools
        
        print("Available tools:", [tool.name for tool in self.all_tools])
        
        # List available resources from both servers
        try:
            monitoring_resources_response = await self.monitoring_session.list_resources()
            self.monitoring_resources = monitoring_resources_response.resources
            print("Monitoring resources:", [resource.uri for resource in self.monitoring_resources])
            
            jira_resources_response = await self.jira_session.list_resources()
            self.jira_resources = jira_resources_response.resources
            print("Jira resources:", [resource.uri for resource in self.jira_resources])
        except Exception as e:
            print(f"Error listing resources: {e}")

    async def process_query(self, query: str, conversation_history=None) -> str:
        """Process a query using ReAct agent and available tools from both servers"""
        if not self.monitoring_session or not self.jira_session:
            return "Error: Not connected to servers. Please connect first."
        
        # Initialize conversation history if not provided
        if conversation_history is None:
            conversation_history = []
        
        # Combine the system prompts
        combined_system_prompt = f"""
        You are an AWS Monitoring and Jira Ticket Agent with access to multiple tools.
        
        MONITORING CAPABILITIES:
        {self.monitoring_system_prompt}
        
        JIRA TICKET CREATION CAPABILITIES:
        {self.jira_system_prompt}
        
        You should first analyze CloudWatch logs and alarms using the monitoring tools.
        If you identify issues, USE THE SEARCH_AWS_REMEDIATION TOOL FIRST to find official AWS remediation solutions,
        and THEN use create_jira_issue tool to create a ticket that includes these AWS-recommended steps.
        
        IMPORTANT: Always create comprehensive tickets that include all information found during monitoring 
        and the AWS remediation steps found via search_aws_remediation. When the user says "create a JIRA ticket", 
        you MUST run search_aws_remediation BEFORE creating the ticket, and include those remediation steps in the ticket.
        
        FOLLOW THESE STEPS IN ORDER WHEN CREATING A TICKET:
        1. Analyze logs or collect issue information (if not done already)
        2. Search for AWS remediation steps using search_aws_remediation
        3. Create the JIRA ticket using create_jira_issue, including the remediation steps from step 2
        
        Available tools:
        - Monitoring tools: list_cloudwatch_dashboards, fetch_cloudwatch_logs_for_service, get_cloudwatch_alarms_for_service, get_dashboard_summary
        - Jira tools: search_aws_remediation, create_jira_issue
        
        The user MUST EXPLICITLY ask you to create a ticket, don't create tickets unprompted.
        """
        
        try:
            # Create a model instance
            model = ChatBedrock(model_id=CLAUDE_3_5_HAIKU)
            
            # Create a ReAct agent with all tools
            agent = create_react_agent(
                model,
                self.all_tools
            )
            print(f"Initialized the AWS combined ReAct agent...")
            
            # Format messages including conversation history
            formatted_messages = [
                {"role": "system", "content": combined_system_prompt}
            ]
            
            # Add conversation history
            for message in conversation_history:
                formatted_messages.append(message)
                
            # Add current query
            formatted_messages.append({"role": "user", "content": query})
            
            print(f"Formatted messages prepared")
            
            # Invoke the agent
            response = await agent.ainvoke({"messages": formatted_messages})
            
            # Process the response
            if response and "messages" in response and response["messages"]:
                last_message = response["messages"][-1]
                if isinstance(last_message, dict) and "content" in last_message:
                    # Save this interaction in the conversation history
                    conversation_history.append({"role": "user", "content": query})
                    conversation_history.append({"role": "assistant", "content": last_message["content"]})
                    return last_message["content"], conversation_history
                else:
                    conversation_history.append({"role": "user", "content": query})
                    conversation_history.append({"role": "assistant", "content": str(last_message.content)})
                    return str(last_message.content), conversation_history
            else:
                return "No valid response received", conversation_history
                
        except Exception as e:
            print(f"Error details: {e}")
            import traceback
            traceback.print_exc()
            return f"Error processing query: {str(e)}", conversation_history

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nAWS Monitoring and Jira Ticket Client Started!")
        print("Type your queries or 'quit' to exit.")
        print("\nExample queries you can try:")
        print("- Show me the CloudWatch logs for EC2 in the last 24 hours")
        print("- Check if there are any errors in the Lambda logs")
        print("- Create a Jira ticket for the S3 access denied issues")
        print("- What remediation steps does AWS recommend for RDS performance issues?")

        # Initialize conversation history
        conversation_history = []

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == 'quit':
                    break

                response, conversation_history = await self.process_query(query, conversation_history)
                print("\n" + response)

            except Exception as e:
                print(f"\nError: {str(e)}")

    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()

async def main():
    client = MCPClient()
    try:
        await client.connect_to_servers()
        await client.chat_loop()
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())