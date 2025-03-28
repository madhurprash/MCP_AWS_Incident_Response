# jira_server.py
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from mcp.server.fastmcp import FastMCP, Context

# Create MCP server for Jira ticket creation
jira_server = FastMCP("AWS-Jira-Tickets-Server")

# Mock JiraAPIWrapper for demonstration
class JiraAPIWrapper:
    def issue_create(self, fields_json):
        fields = json.loads(fields_json)
        issue_key = f"{fields['project']['key']}-{int(datetime.now().timestamp())}"
        return {
            "id": f"ID-{issue_key}",
            "key": issue_key,
            "self": f"https://your-jira-instance.atlassian.net/rest/api/2/issue/{issue_key}"
        }

@jira_server.tool()
def create_jira_issue(
    summary: str, 
    description: str, 
    project_key: str = None, 
    issue_type: str = "Task", 
    assignee: str = None,
    priority: str = "Medium",
    labels: Optional[list] = None
) -> Dict[str, Any]:
    """
    Creates a new issue in Jira with the specified details.
    
    Args:
        summary (str): Summary/title of the issue
        description (str): Detailed description of the issue
        project_key (str, optional): Jira project key (defaults to environment variable)
        issue_type (str, optional): Type of issue (default: Task)
        assignee (str, optional): Username of the assignee
        priority (str, optional): Priority of the issue (default: Medium)
        labels (list, optional): List of labels to apply to the issue
        
    Returns:
        Dictionary with issue creation details
    """
    try:
        # Use project key from environment variables if not provided
        if not project_key:
            project_key = os.environ.get("PROJECT_KEY", "ASCRT")
            
        print(f"Creating Jira issue with project_key: {project_key}")
        
        jira = JiraAPIWrapper()
        
        # Create the issue fields dictionary
        issue_fields = {
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "project": {"key": project_key},
            "priority": {"name": priority}
        }
        
        if assignee:
            issue_fields["assignee"] = {"name": assignee}
            
        if labels:
            issue_fields["labels"] = labels
        
        # Convert dictionary to JSON string
        issue_fields_json = json.dumps(issue_fields)
        print(f"Sending JSON: {issue_fields_json}")
        
        # Pass the JSON string to the issue_create method
        result = jira.issue_create(issue_fields_json)
        print(f"CREATED THE JIRA TICKET! Check your JIRA dashboard.")
        
        return {
            "status": "success",
            "message": "Jira issue created successfully",
            "issue_key": result.get("key"),
            "issue_id": result.get("id"),
            "issue_url": result.get("self"),
            "created_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {
            "status": "error", 
            "message": f"Error creating Jira issue: {str(e)}"
        }

@jira_server.prompt()
def create_aws_jira_tickets() -> str:
    """Prompt for creating Jira tickets for AWS issues."""
    return """
    You are the AWS Jira Ticket Creation Agent. You have access to a tool that can create well-formatted Jira tickets for AWS issues and incidents.

    Your workflow is:
    
    1. **Gather Information for Jira Ticket:**
       - Collect necessary details about the AWS issue from the user.
       - Ensure you have enough information to create a comprehensive ticket.
       - Ask clarifying questions if needed to get complete information.
    
    2. **Create Well-Structured Jira Tickets:**
       - Use the `create_jira_issue` tool to create formatted tickets.
       - Structure the ticket with a clear summary, detailed description, and recommended actions.
       - Use appropriate issue types, priorities, and labels based on the nature of the problem.
    
    **Guidelines for Creating Effective Jira Tickets:**
    
    - **Summary:** Keep it concise yet descriptive. Format as: "[SERVICE] - [BRIEF ISSUE DESCRIPTION]" 
      Example: "EC2 - High CPU Utilization on Production Servers"
    
    - **Description:** Structure with the following sections:
      * **Issue:** Detailed explanation of the problem
      * **Impact:** Who/what is affected and how severely
      * **Evidence:** Relevant log excerpts, timestamps, and metrics
      * **Recommendations:** Suggested resolution steps
    
    - **Issue Types:**
      * **Bug:** For software or configuration errors
      * **Task:** For remediation work
      * **Incident:** For security or operational issues requiring immediate attention
      
    - **Priorities:**
      * **Highest/Critical:** Service outage or severe security issue
      * **High:** Significant impact to service or performance
      * **Medium:** Limited impact but requires attention
      * **Low:** Minor issue with minimal impact
    
    When communicating with users:
    1. Confirm ticket details before creation
    2. Provide a summary of the created ticket
    3. Suggest any follow-up actions
    
    Your goal is to ensure AWS issues are properly documented in Jira for tracking and resolution.
    """

if __name__ == "__main__":
    jira_server.run(transport='stdio')