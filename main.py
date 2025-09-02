"""
Billing MCP Server - Model Context Protocol server using FastMCP for HTTP transport.
This server provides MCP tools for billing system account and subscription data for LangGraph workflows.
"""

import json
import logging
import os
import sys
import uuid
from typing import Dict, Any, Optional, List

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

from utils.security_manager import secure_endpoint, initialize_security_manager

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("billing_mcp")

# Security system is imported above

# Billing system configuration
BILLING_CONFIG = {
    "base_url": os.getenv("BILLING_BASE_URL"),
    "client_id": os.getenv("BILLING_CLIENT_ID"),
    "client_secret": os.getenv("BILLING_CLIENT_SECRET"),
}

# AWS Secrets Manager configuration
AWS_SECRET_ARN = os.getenv("AWS_SECRET_ARN")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AUTH_METHOD = os.getenv("AUTH_METHOD", "aws_secrets_manager")

# Default API key for Claude Desktop (when no key is provided)
DEFAULT_API_KEY = os.getenv("DEFAULT_API_KEY")

# Initialize security manager with AWS Secrets Manager
logger.info("Initializing security manager with AWS Secrets Manager")
logger.info(f"   Secret ARN: {AWS_SECRET_ARN}")
logger.info(f"   Region: {AWS_REGION}")
logger.info(f"   Auth Method: {AUTH_METHOD}")

try:
    security_manager = initialize_security_manager(AWS_SECRET_ARN)
    logger.info("Security manager initialized successfully with AWS Secrets Manager")
except Exception as e:
    logger.error(f"Failed to initialize security manager: {e}")
    security_manager = initialize_security_manager(None)

# Server configuration  
SERVER_HOST = os.getenv("SERVER_HOST")
SERVER_PORT = os.getenv("SERVER_PORT")

if not SERVER_HOST:
    raise ValueError("SERVER_HOST environment variable is required")
if not SERVER_PORT:
    raise ValueError("SERVER_PORT environment variable is required")

try:
    SERVER_PORT = int(SERVER_PORT)
except ValueError:
    raise ValueError("SERVER_PORT must be a valid integer")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("Billing_MCP_Server")

# Global HTTP client for Billing API
class BillingClient:
    """Billing system API client with authentication and retry logic"""
    
    def __init__(self):
        self.client = None
        self.access_token = None
        
    async def _ensure_client(self):
        """Ensure HTTP client is initialized"""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True
            )
            
    async def _get_access_token(self) -> str:
        """Get or refresh OAuth access token"""
        if self.access_token:
            return self.access_token
            
        await self._ensure_client()
        
        logger.info("Requesting new billing system access token")
        token_url = f"{BILLING_CONFIG['base_url']}/oauth/token"
        
        token_data = {
            "client_id": BILLING_CONFIG["client_id"],
            "client_secret": BILLING_CONFIG["client_secret"],
            "grant_type": "client_credentials"
        }
        
        response = await self.client.post(token_url, data=token_data)
        response.raise_for_status()
        
        token_info = response.json()
        self.access_token = token_info["access_token"]
        
        return self.access_token
        
    async def request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Make authenticated request to billing system API"""
        await self._ensure_client()
        token = await self._get_access_token()
        
        url = f"{BILLING_CONFIG['base_url']}{endpoint}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Content-Type"] = "application/json"
        
        # Add unique request ID for tracking
        headers["X-Request-Id"] = str(uuid.uuid4())[:8]
        
        try:
            response = await self.client.request(method, url, headers=headers, **kwargs)
            
            # Reset token on 401 to force refresh
            if response.status_code == 401:
                self.access_token = None
                
            return response
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Billing system API error: {e}")
            raise
            
    async def close(self):
        """Close the HTTP client"""
        if self.client:
            await self.client.aclose()

# Global billing client instance
billing_client = BillingClient()

# Global transport mode (set at startup)
TRANSPORT_MODE = "stdio"  # Default to stdio

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


# Utility functions
async def billing_query_all(query: str, page_size: int = 100) -> List[Dict[str, Any]]:
    """Execute billing query with pagination using action/query and action/queryMore"""
    all_records = []
    
    logger.debug(f"Executing billing query: {query[:100]}... with page_size: {page_size}")


    # Initial query
    response = await billing_client.request(
        "POST", 
        "/v1/action/query",
        json={"queryString": query, "conf": {"batchSize": page_size}}
    )
    
    if response.status_code != 200:
        raise httpx.HTTPStatusError(
            f"Query failed with status {response.status_code}", 
            request=response.request, 
            response=response
        )
    
    data = response.json()
    all_records.extend(data.get("records", []))
    
    return all_records


def ok(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {"success": True}
    out.update(payload)
    return out

def err(code: str, message: str, **kwargs: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"is_error": True, "code": code, "message": message}
    if kwargs:
        out.update(kwargs)
    return out

def clamp_page_size(page_size: int, minimum: int = 1, maximum: int = 100) -> int:
    try:
        page_size = int(page_size)
    except Exception:
        page_size = maximum
    return max(minimum, min(page_size, maximum))


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


# FastMCP Tools
@mcp.tool()
@secure_endpoint('account')
async def get_account(account_id: str) -> str:
    """
    Get detailed account information by ID.
    
    Args:
        account_id: The billing system account ID
        
    Returns:
        JSON string with account details including basic info and metrics
    """
    
    logger.info(f"[get_account] account_id={account_id}")
    
    try:
        resp = await billing_client.request("GET", f"/v1/accounts/{account_id}")
        if resp.status_code == 404:
            return json.dumps(err("ACCOUNT_NOT_FOUND", f"Account {account_id} not found", account_id=account_id))
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(ok({
            "account_id": account_id,
            "basicInfo": data.get("basicInfo", {}),
            "billingAndPayment": data.get("billingAndPayment", {}),
            "metrics": data.get("metrics", {}),
        }))
    except Exception as e:
        logger.exception("get_account failed")
        return json.dumps(err("GET_ACCOUNT_FAILED", str(e), account_id=account_id))
        

@mcp.tool()
@secure_endpoint('default')
async def query_billing(billingquery: str, batch_size: int = 100) -> str:
    """
    Execute a custom billing query.
    Uses the billing system's action/query API with configurable batch size.
    
    Args:
        billingquery: The billing query to execute (e.g., "SELECT Id, Name FROM Account")
        batch_size: Batch size for pagination (default 100, max 2000)
        
    Returns:
        JSON string with query results
    """
    logger.info(f"[query_billing] query='{billingquery[:100]}...', batch_size={batch_size}")
    
    try:
        # Validate and clamp batch_size
        batch_size = min(max(batch_size, 1), 2000)  # Billing system query limit
        
        # Basic query validation
        if not billingquery or not billingquery.strip():
            return json.dumps(err("INVALID_QUERY", "Billing query cannot be empty"))
        
        query = billingquery.strip()
        
        # Execute billing query with pagination using the billing system's action/query API
        # API call format: {"queryString": "SELECT ...", "conf": {"batchSize": N}}
        records = await billing_query_all(query, batch_size)
        
        return json.dumps(ok({
            "query": query,
            "records": records,
            "count": len(records),
            "batch_size": batch_size
        }))
        
    except Exception as e:
        logger.exception("query_billing failed")
        return json.dumps(err("QUERY_BILLING_FAILED", str(e), query=billingquery[:200]))

@mcp.tool()
@secure_endpoint('subscription')
async def get_subscription(subscription_id: str) -> str:
    """
    Get detailed subscription information by ID.
    
    Args:
        subscription_id: The billing system subscription ID
        
    Returns:
        JSON string with subscription details
    """
    logger.info(f"[get_subscription] subscription_id={subscription_id}")
    
    try:
        response = await billing_client.request(
            "GET", 
            f"/v1/subscriptions/{subscription_id}"
        )
        
        if response.status_code == 404:
            return json.dumps(err("SUBSCRIPTION_NOT_FOUND", f"Subscription {subscription_id} not found", subscription_id=subscription_id))
        
        response.raise_for_status()
        subscription_data = response.json()
        
        return json.dumps(ok({
            "subscription_id": subscription_id,
            "subscription_data": subscription_data
        }))
        
    except Exception as e:
        logger.exception("get_subscription failed")
        return json.dumps(err("GET_SUBSCRIPTION_FAILED", str(e), subscription_id=subscription_id))











# Update available tools log
logger.info("Available tools: get_account, query_billing, get_subscription")

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
# FastMCP handles cleanup automatically, but we can add a custom cleanup if needed
# The HTTP client will be closed when the process exits

if __name__ == "__main__":
    # Check command line arguments for transport type
    transport_type = "stdio"  # Default to stdio for Claude Desktop
    
    if "--http" in sys.argv:
        transport_type = "streamable-http"
    
    # Set global transport mode
    TRANSPORT_MODE = transport_type
    
    if transport_type == "stdio":
        # Log startup info for stdio
        logger.info("Billing MCP Server starting with stdio transport for Claude Desktop...")
        logger.info("Available tools: get_account, query_billing, get_subscription")
        
        # Run with stdio transport for Claude Desktop
        mcp.run()
    else:
        # Log startup info for HTTP
        logger.info(f"Billing MCP Server starting with HTTP transport...")
        logger.info(f"Server: http://{SERVER_HOST}:{SERVER_PORT}")
        logger.info(f"MCP endpoint: http://{SERVER_HOST}:{SERVER_PORT}")
        logger.info(f"Available tools: get_account, query_billing, get_subscription")
        
        # Run the FastMCP server with HTTP transport
        mcp.run(transport="streamable-http", host=SERVER_HOST, port=SERVER_PORT)