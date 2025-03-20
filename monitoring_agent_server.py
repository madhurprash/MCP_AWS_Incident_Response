# monitoring_server.py
import boto3
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from mcp.server.fastmcp import FastMCP, Context

# Create MCP server
# This monitoring server contains information about the cloudwatch logs
# in a user's AWS account. It will be able to fetch recent logs
# for a specified service and time period
monitoring_server = FastMCP("AWS-Monitoring-Server")

# Initialize AWS clients
cloudwatch_logs_client = boto3.client('logs')
cloudwatch_client = boto3.client('cloudwatch')

"""
This file contains the server information for enabling our application
with tools that the model can access using MCP. This is the first server that 
focuses on the monitoring aspect of the application. This means that this server
code has tools to fetch cloudwatch logs for a given service provided by the user.

The workflow that is followed in this server is: The tool provides users with
the available services that they can monitor, then get the most recent cloudwatch logs for 
that given service, and then check for the cloudwatch alarms. This information is then used
by the other server to take further steps, such as diagnose the issue and then a resolution agent
to create tickets.
"""

@monitoring_server.tool()
async def fetch_cloudwatch_logs(
    service_name: str,
    days: int = 30,
    max_logs: int = 100,
    filter_pattern: str = ""
) -> Dict:
    """
    Fetches CloudWatch logs for a specified service for the past N days.
    
    Args:
        service_name: The name of the service to fetch logs for
        days: Number of days to look back (default: 2)
        max_logs: Maximum number of log events to return (default: 100)
        filter_pattern: Optional filter pattern to apply to logs
        
    Returns:
        Dictionary containing log groups, streams, and events
    """
    try:
        # Calculate the start time based on the number of days
        start_time = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)
        end_time = int(datetime.utcnow().timestamp() * 1000)
        
        # Find log groups related to the requested service
        log_groups_response = cloudwatch_logs_client.describe_log_groups(
            logGroupNamePrefix=f"/{service_name}",
            limit=10
        )
        
        log_groups = log_groups_response.get('logGroups', [])
        if not log_groups:
            return {"error": f"No log groups found for service: {service_name}"}
        
        results = {"service": service_name, "log_groups": {}}
        
        # For each log group, get the most recent log streams
        for log_group in log_groups:
            log_group_name = log_group['logGroupName']
            results["log_groups"][log_group_name] = {"streams": {}}
            
            # Get the most recent log streams for this group
            streams_response = cloudwatch_logs_client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=5
            )
            
            log_streams = streams_response.get('logStreams', [])
            if not log_streams:
                results["log_groups"][log_group_name]["error"] = "No recent log streams found"
                continue
            
            # For each stream, get the log events
            for stream in log_streams:
                stream_name = stream['logStreamName']
                
                logs_response = cloudwatch_logs_client.filter_log_events(
                    logGroupName=log_group_name,
                    logStreamNames=[stream_name],
                    startTime=start_time,
                    endTime=end_time,
                    filterPattern=filter_pattern,
                    limit=max_logs
                )
                
                events = logs_response.get('events', [])
                
                # Format the log events for readability
                formatted_events = []
                for event in events:
                    timestamp = datetime.fromtimestamp(event['timestamp'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    formatted_events.append({
                        "timestamp": timestamp,
                        "message": event['message']
                    })
                
                results["log_groups"][log_group_name]["streams"][stream_name] = formatted_events
        
        # Add summary information
        total_events = sum(len(stream) 
                          for group in results["log_groups"].values() 
                          for stream in group.get("streams", {}).values())
        
        results["summary"] = {
            "total_log_groups": len(results["log_groups"]),
            "total_events": total_events,
            "time_period": f"Past {days} days ({datetime.fromtimestamp(start_time/1000).strftime('%Y-%m-%d %H:%M:%S')} to {datetime.fromtimestamp(end_time/1000).strftime('%Y-%m-%d %H:%M:%S')})"
        }
        
        return results
    
    except Exception as e:
        return {"error": f"Error fetching CloudWatch logs: {str(e)}"}

@monitoring_server.resource("cloudwatch://alarms")
async def get_cloudwatch_alarms() -> str:
    """Get all CloudWatch alarms in the account"""
    try:
        response = cloudwatch_client.describe_alarms()
        alarms = response.get('MetricAlarms', [])
        
        formatted_alarms = []
        for alarm in alarms:
            formatted_alarms.append({
                'name': alarm.get('AlarmName'),
                'state': alarm.get('StateValue'),
                'metric': alarm.get('MetricName'),
                'namespace': alarm.get('Namespace')
            })
            
        return f"CloudWatch Alarms:\n{formatted_alarms}"
    except Exception as e:
        return f"Error fetching CloudWatch alarms: {str(e)}"

@monitoring_server.prompt()
def analyze_aws_logs() -> str:
    """Prompt to analyze AWS CloudWatch logs"""
    return """
    You are the monitoring agent responsible for analyzing CloudWatch logs for AWS services.
    Your tasks include:
    1. Fetch recent CloudWatch logs for the requested service.
    2. Identify any errors, warnings, or anomalies in the logs.
    3. Look for patterns or recurring issues.
    4. Provide a summary of log findings and any potential actions needed.
    5. Report your findings to the user in a clear, organized manner.
    
    First, you may need to list available services to help the user choose which service logs to analyze.
    Then, fetch and analyze the logs for their chosen service for the specified time period.
    Be thorough in your investigation but concise in your reporting.
    
    Always first give the user the list of services they can get cloudwatch logs on, then get the logs and then fetch 
    any relevant alarms.
    """

if __name__ == "__main__":
    monitoring_server.run(transport='stdio')
