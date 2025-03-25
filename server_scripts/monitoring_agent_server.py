# monitoring_server.py
import json
import boto3
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from mcp.server.fastmcp import FastMCP, Context

# Create MCP server
# This monitoring server contains information about the cloudwatch logs
# in a user's AWS account. It will be able to fetch recent logs
# for a specified service and time period
monitoring_server = FastMCP("AWS-Monitoring-Server")

# Initialize AWS clients
# Define boto3 and AWS clients
cloudwatch_client = boto3.client('cloudwatch')
cloudtrail_client = boto3.client('cloudtrail')
logs_client = boto3.client('logs')
xray_client = boto3.client('xray')
autoscaling_client = boto3.client('autoscaling')
ec2_client = boto3.client('ec2')
health_client = boto3.client('health')

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
def fetch_cloudwatch_logs_for_service(
    service_name: str,
    days: int = 3,
    filter_pattern: str = ""
) -> Dict[str, Any]:
    """
    Fetches CloudWatch logs for a specified service for the given number of days.
    
    Args:
        service_name (str): The name of the service to fetch logs for (e.g., "ec2", "lambda", "rds")
        days (int): Number of days of logs to fetch (default: 3)
        filter_pattern (str): Optional CloudWatch Logs filter pattern
        
    Returns:
        Dictionary with log groups and their recent log events
    """
    try:
        service_log_prefixes = {
        "ec2": ["/aws/ec2", "/var/log"],
        "lambda": ["/aws/lambda"],
        "rds": ["/aws/rds"],
        "eks": ["/aws/eks"],
        "apigateway": ["/aws/apigateway"],
        "cloudtrail": ["/aws/cloudtrail"],
        "s3": ["/aws/s3", "/aws/s3-access"],
        "vpc": ["/aws/vpc"],
        "waf": ["/aws/waf"],
        "bedrock": ["/bedrockInvocationlogs"],
        "iam": ["/aws/dummy-security-logs"] 
        }

        # Default to searching all log groups if service isn't in our mapping
        prefixes = service_log_prefixes.get(service_name.lower(), [""])
        print(f"Fetching logs for the service: {prefixes}")
        
        # Find all log groups for this service
        log_groups = []
        for prefix in prefixes:
            paginator = logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate(logGroupNamePrefix=prefix):
                log_groups.extend([group['logGroupName'] for group in page['logGroups']])
        
        if not log_groups:
            return {"status": "warning", "message": f"No log groups found for service: {service_name}"}
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        # Convert to milliseconds since epoch
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
        
        results = {}
        
        # Iterate through log groups and fetch log events
        for log_group in log_groups:
            try:
                # First get log streams
                response = logs_client.describe_log_streams(
                    logGroupName=log_group,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5  # Get the 5 most recent streams
                )
                print(f"fetching logs for log group {log_group}: {response}")
                streams = response.get('logStreams', [])
                
                if not streams:
                    results[log_group] = {"status": "info", "message": "No log streams found"}
                    continue
                
                group_events = []
                
                # For each stream, get recent log events
                for stream in streams:
                    stream_name = stream['logStreamName']
                    
                    # If filter pattern is provided, use filter_log_events
                    if filter_pattern:
                        filter_response = logs_client.filter_log_events(
                            logGroupName=log_group,
                            logStreamNames=[stream_name],
                            startTime=start_time_ms,
                            endTime=end_time_ms,
                            filterPattern=filter_pattern,
                            limit=100
                        )
                        events = filter_response.get('events', [])
                    else:
                        # Otherwise use get_log_events
                        log_response = logs_client.get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream_name,
                            startTime=start_time_ms,
                            endTime=end_time_ms,
                            limit=100
                        )
                        events = log_response.get('events', [])
                    
                    # Process and add events
                    for event in events:
                        # Convert timestamp to readable format
                        timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
                        formatted_event = {
                            'timestamp': timestamp.isoformat(),
                            'message': event['message']
                        }
                        group_events.append(formatted_event)
                
                # Sort all events by timestamp (newest first)
                group_events.sort(key=lambda x: x['timestamp'], reverse=True)
                
                results[log_group] = {
                    "status": "success",
                    "events_count": len(group_events),
                    "events": group_events[:100]  # Limit to 100 most recent events
                }
                
            except Exception as e:
                results[log_group] = {"status": "error", "message": str(e)}
        
        return {
            "service": service_name,
            "time_range": f"{start_time.isoformat()} to {end_time.isoformat()}",
            "log_groups_count": len(log_groups),
            "log_groups": results
        }
        
    except Exception as e:
        print(f"Error fetching logs for service {service_name}: {e}")
        return {"status": "error", "message": str(e)}
    
@monitoring_server.tool()
def list_cloudwatch_dashboards() -> Dict[str, Any]:
    """
    Lists all CloudWatch dashboards in the AWS account.

    Returns:
        Dict[str, Any]: A dictionary containing the list of dashboard names and their ARNs.
    """
    try:
        dashboards = []
        paginator = cloudwatch_client.get_paginator('list_dashboards')
        for page in paginator.paginate():
            for entry in page.get('DashboardEntries', []):
                dashboards.append({
                    'DashboardName': entry.get('DashboardName'),
                    'DashboardArn': entry.get('DashboardArn')
                })

        return {
            'status': 'success',
            'dashboard_count': len(dashboards),
            'dashboards': dashboards
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@monitoring_server.tool()
def get_cloudwatch_alarms_for_service(service_name: str = None) -> Dict[str, Any]:
    """
    Fetches CloudWatch alarms, optionally filtering by service.
    
    Args:
        service_name (str, optional): The name of the service to filter alarms for
        
    Returns:
        Dictionary with alarm information
    """
    try:
        response = cloudwatch_client.describe_alarms()
        alarms = response.get('MetricAlarms', [])
        
        formatted_alarms = []
        for alarm in alarms:
            namespace = alarm.get('Namespace', '').lower()
            
            # Filter by service if provided
            if service_name and service_name.lower() not in namespace:
                continue
                
            formatted_alarms.append({
                'name': alarm.get('AlarmName'),
                'state': alarm.get('StateValue'),
                'metric': alarm.get('MetricName'),
                'namespace': alarm.get('Namespace')
            })
        
        return {
            "alarm_count": len(formatted_alarms),
            "alarms": formatted_alarms
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@monitoring_server.tool()
def get_dashboard_summary(dashboard_name: str) -> Dict[str, Any]:
    """
    Retrieves and summarizes the configuration of a specified CloudWatch dashboard.

    Args:
        dashboard_name (str): The name of the CloudWatch dashboard.

    Returns:
        Dict[str, Any]: A summary of the dashboard's widgets and their configurations.
    """
    try:
        # Fetch the dashboard configuration
        response = cloudwatch_client.get_dashboard(DashboardName=dashboard_name)
        dashboard_body = response.get('DashboardBody', '{}')
        dashboard_config = json.loads(dashboard_body)

        # Summarize the widgets in the dashboard
        widgets_summary = []
        for widget in dashboard_config.get('widgets', []):
            widget_summary = {
                'type': widget.get('type'),
                'x': widget.get('x'),
                'y': widget.get('y'),
                'width': widget.get('width'),
                'height': widget.get('height'),
                'properties': widget.get('properties', {})
            }
            widgets_summary.append(widget_summary)

        return {
            'dashboard_name': dashboard_name,
            'widgets_count': len(widgets_summary),
            'widgets_summary': widgets_summary
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@monitoring_server.prompt()
def analyze_aws_logs() -> str:
    """Prompt to analyze AWS resources, including CloudWatch logs, alarms, and dashboards."""
    return """
    You are the monitoring agent responsible for analyzing AWS resources, including CloudWatch logs, alarms, and dashboards. Your tasks include:

    1. **List Available CloudWatch Dashboards:**
       - Utilize the `list_cloudwatch_dashboards` tool to retrieve a list of all CloudWatch dashboards in the AWS account.
       - Provide the user with the names and descriptions of these dashboards, offering a brief overview of their purpose and contents.

    2. **Fetch Recent CloudWatch Logs for Requested Services:**
       - When a user specifies a service (e.g., EC2, Lambda, RDS), use the `fetch_cloudwatch_logs_for_service` tool to retrieve the most recent logs for that service.
       - Analyze these logs to identify any errors, warnings, or anomalies.
       - Summarize your findings, highlighting any patterns or recurring issues, and suggest potential actions or resolutions.

    3. **Retrieve and Summarize CloudWatch Alarms:**
       - If the user inquires about alarms or if log analysis indicates potential issues, use the `get_cloudwatch_alarms_for_service` tool to fetch relevant alarms.
       - Provide details about active alarms, including their state, associated metrics, and any triggered thresholds.
       - Offer recommendations based on the alarm statuses and suggest possible remediation steps.

    4. **Analyze Specific CloudWatch Dashboards:**
       - When a user requests information about a particular dashboard, use the `get_dashboard_summary` tool to retrieve and summarize its configuration.
       - Detail the widgets present on the dashboard, their types, and the metrics or logs they display.
       - Provide insights into the dashboard's focus areas and how it can be utilized for monitoring specific aspects of the AWS environment.

    **Guidelines:**

    - Always begin by listing the available CloudWatch dashboards to inform the user of existing monitoring setups.
    - When analyzing logs or alarms, be thorough yet concise, ensuring clarity in your reporting.
    - Avoid making assumptions; base your analysis strictly on the data retrieved from AWS tools.
    - Clearly explain the available AWS services and their monitoring capabilities when prompted by the user.

    **Available AWS Services for Monitoring:**

    - **EC2/Compute Instances** [ec2]
    - **Lambda Functions** [lambda]
    - **RDS Databases** [rds]
    - **EKS Kubernetes** [eks]
    - **API Gateway** [apigateway]
    - **CloudTrail** [cloudtrail]
    - **S3 Storage** [s3]
    - **VPC Networking** [vpc]
    - **WAF Web Security** [waf]
    - **Bedrock AI** [bedrock]
    - **IAM Logs** [iam] (Use this option when users inquire about security logs or events.)

    Your role is to assist users in monitoring and analyzing their AWS resources effectively, providing actionable insights based on the data available.
    """

if __name__ == "__main__":
    monitoring_server.run(transport='stdio')
