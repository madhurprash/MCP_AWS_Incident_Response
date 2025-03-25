# diagnosis_agent_server.py
import os
import boto3
import requests
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP

# Create MCP server
diagnosis_server = FastMCP("AWS-Diagnosis-Server")

# Set up Tavily API key
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "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")
if not TAVILY_API_KEY:
    print("Warning: TAVILY_API_KEY not found in environment variables")

@diagnosis_server.tool()
def diagnose_and_suggest_remediation(monitoring_report: str) -> Dict[str, Any]:
    """
    Analyzes monitoring report to identify security issues, searches for remediation steps,
    and returns a comprehensive diagnosis with suggested fixes.
    
    Args:
        monitoring_report (str): Full report from monitoring agent with security findings
        
    Returns:
        Dictionary with identified issues and remediation recommendations
    """
    try:
        # Extract security issues from monitoring report
        security_issues = []
        
        # Common security issues to look for
        issue_keywords = [
            "root account login", 
            "mfa disabled", 
            "privilege escalation", 
            "brute force", 
            "port scanning",
            "cross-account access", 
            "iam policy modified", 
            "vpc flow logs disabled",
            "security group allows unrestricted access",
            "sensitive data accessed",
            "unusual api call",
            "multiple failed login attempts"
        ]
        
        for issue in issue_keywords:
            if issue.lower() in monitoring_report.lower():
                security_issues.append(issue)
        
        if not security_issues:
            # If no specific issues found, search for general AWS security best practices
            return search_tavily_for_remediation("AWS security best practices for cloud environments")
        
        # If multiple issues found, create a consolidated search query
        if len(security_issues) > 1:
            search_query = f"AWS security remediation for {', '.join(security_issues[:3])}"
            if len(security_issues) > 3:
                search_query += f" and {len(security_issues) - 3} other issues"
        else:
            search_query = f"AWS security remediation for {security_issues[0]}"
            
        return search_tavily_for_remediation(search_query, security_issues)
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def search_tavily_for_remediation(search_query: str, identified_issues=None) -> Dict[str, Any]:
    """
    Searches for AWS remediation steps using Tavily search API.
    
    Args:
        search_query (str): Query for Tavily search
        identified_issues (list, optional): List of identified security issues
        
    Returns:
        Dictionary with search results formatted as recommendations
    """
    try:
        if not TAVILY_API_KEY:
            return {
                "status": "error", 
                "message": "Tavily API key not configured"
            }
        
        # Call Tavily API
        response = requests.post(
            "https://api.tavily.com/search",
            headers={"content-type": "application/json"},
            json={
                "api_key": TAVILY_API_KEY,
                "query": search_query,
                "search_depth": "advanced",
                "include_domains": ["aws.amazon.com", "docs.aws.amazon.com"],
                "max_results": 5
            }
        )
        
        if response.status_code != 200:
            return {
                "status": "error",
                "message": f"Tavily API error: {response.text}"
            }
        
        results = response.json()
        
        # Format results for better presentation
        formatted_results = []
        for result in results.get("results", []):
            formatted_results.append({
                "title": result.get("title"),
                "url": result.get("url"),
                "content": result.get("content"),
                "relevance": "High" if "aws.amazon.com" in result.get("url", "") else "Medium"
            })
        
        return {
            "status": "success",
            "search_query": search_query,
            "identified_issues": identified_issues,
            "results_count": len(formatted_results),
            "results": formatted_results
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

@diagnosis_server.prompt()
def diagnose_security_issues() -> str:
    """Prompt to diagnose security issues and provide remediation"""
    return """
    You are a specialized AWS security diagnosis agent that works alongside a monitoring agent.
    
    Your primary responsibility is to:
    1. Analyze monitoring reports to identify security issues and vulnerabilities
    2. Use external knowledge to recommend remediation steps
    3. Present findings in a clear, actionable format
    
    When you receive a monitoring report:
    1. Use the diagnose_and_suggest_remediation tool to search for expert recommendations
    2. Organize remediation steps by priority (Critical, High, Medium, Low)
    3. Include links to AWS documentation when available
    
    Focus on being practical and actionable. Provide specific commands or steps when possible.
    
    Never invent security issues - only diagnose based on what's in the monitoring report.
    """

if __name__ == "__main__":
    diagnosis_server.run(transport='stdio')