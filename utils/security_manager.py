#!/usr/bin/env python3
"""
Security Manager for MCP Server
Handles API Key Authentication, Rate Limiting, and Audit Logging
"""

import json
import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from typing import Dict, Any, Optional

# AWS Secrets Manager imports
import boto3
from botocore.exceptions import ClientError

class AWSSecretsManagerAuth:
    """AWS Secrets Manager integration for API key management."""
    
    def __init__(self, secret_arn: str, region_name: str = 'us-east-1'):
        self.secret_arn = secret_arn
        self.secrets_client = boto3.client('secretsmanager', region_name=region_name)
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes cache
    
    def get_api_keys_from_secrets_manager(self) -> dict:
        """Retrieve API keys from AWS Secrets Manager with caching."""
        # Check cache first
        if 'keys' in self._cache:
            cache_time, keys = self._cache['keys']
            if time.time() - cache_time < self._cache_ttl:
                return keys
        
        try:
            response = self.secrets_client.get_secret_value(
                SecretId=self.secret_arn
            )
            keys = json.loads(response['SecretString'])
            
            # Cache the result
            self._cache['keys'] = (time.time(), keys)
            return keys
            
        except ClientError as e:
            print(f"Error retrieving secret: {e}")
            return {}
    
    def validate_api_key(self, api_key: str) -> dict:
        """Validate API key against Secrets Manager."""
        valid_keys = self.get_api_keys_from_secrets_manager()
        
        if api_key in valid_keys:
            return valid_keys[api_key]
        return None

# APIKeyManager class removed - using AWSSecretsManagerAuth directly

class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests = defaultdict(deque)
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
    
    def _cleanup_old_requests(self):
        """Remove old requests to prevent memory leaks."""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = now - 3600  # Remove requests older than 1 hour
        for client_id in list(self.requests.keys()):
            client_requests = self.requests[client_id]
            while client_requests and client_requests[0] <= cutoff_time:
                client_requests.popleft()
            
            # Remove empty entries
            if not client_requests:
                del self.requests[client_id]
        
        self.last_cleanup = now
    
    def is_allowed(self, client_id: str, limit: int, window: int) -> Dict[str, Any]:
        """Check if request is allowed and return rate limit info."""
        self._cleanup_old_requests()
        
        now = time.time()
        client_requests = self.requests[client_id]
        
        # Remove old requests outside window
        while client_requests and client_requests[0] <= now - window:
            client_requests.popleft()
        
        current_count = len(client_requests)
        
        if current_count >= limit:
            return {
                "allowed": False,
                "current_count": current_count,
                "limit": limit,
                "window": window,
                "reset_time": client_requests[0] + window if client_requests else now + window
            }
        
        # Add current request
        client_requests.append(now)
        
        return {
            "allowed": True,
            "current_count": current_count + 1,
            "limit": limit,
            "window": window,
            "reset_time": now + window
        }

class AuditLogger:
    """Comprehensive audit logging system."""
    
    def __init__(self, log_file: str = None):
        # Use environment variable or default to relative path in current directory
        if log_file is None:
            import os
            log_file = os.getenv("AUDIT_LOG_FILE", "audit.log")
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Create console handler for critical events (always available)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        # Add console handler
        self.logger.addHandler(console_handler)
        
        # Try to create file handler, but don't fail if we can't write to filesystem
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            self.file_logging_enabled = True
        except (OSError, PermissionError) as e:
            # File logging not available (e.g., read-only filesystem)
            self.file_logging_enabled = False
            self.logger.warning(f"File logging disabled: {e}")
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def log_request(self, request_data: Dict[str, Any]):
        """Log API request."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "api_request",
            "request_id": request_data.get("request_id"),
            "user_id": request_data.get("user_id"),
            "api_key": request_data.get("api_key"),
            "endpoint": request_data.get("endpoint"),
            "method": request_data.get("method"),
            "parameters": request_data.get("parameters", {}),
            "response_time_ms": request_data.get("response_time_ms"),
            "status": request_data.get("status", "success")
        }
        
        # Add optional client info if available
        if request_data.get("client_ip"):
            audit_entry["client_ip"] = request_data.get("client_ip")
        if request_data.get("user_agent"):
            audit_entry["user_agent"] = request_data.get("user_agent")
        
        self.logger.info(json.dumps(audit_entry))
    
    def log_security_event(self, event_data: Dict[str, Any]):
        """Log security-related events."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "security_event",
            "request_id": event_data.get("request_id"),
            "severity": event_data.get("severity", "medium"),
            "event": event_data.get("event"),
            "user_id": event_data.get("user_id"),
            "api_key": event_data.get("api_key"),
            "details": event_data.get("details", {})
        }
        
        # Add optional client info if available
        if event_data.get("client_ip"):
            audit_entry["client_ip"] = event_data.get("client_ip")
        if event_data.get("user_agent"):
            audit_entry["user_agent"] = event_data.get("user_agent")
        
        if event_data.get("severity") == "high":
            self.logger.error(json.dumps(audit_entry))
        else:
            self.logger.warning(json.dumps(audit_entry))
    
    def log_rate_limit_event(self, event_data: Dict[str, Any]):
        """Log rate limiting events."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "rate_limit",
            "request_id": event_data.get("request_id"),
            "user_id": event_data.get("user_id"),
            "api_key": event_data.get("api_key"),
            "endpoint": event_data.get("endpoint"),
            "current_count": event_data.get("current_count"),
            "limit": event_data.get("limit"),
            "window": event_data.get("window"),
            "reset_time": event_data.get("reset_time")
        }
        
        # Add optional client info if available
        if event_data.get("client_ip"):
            audit_entry["client_ip"] = event_data.get("client_ip")
        if event_data.get("user_agent"):
            audit_entry["user_agent"] = event_data.get("user_agent")
        
        self.logger.warning(json.dumps(audit_entry))

class SecurityManager:
    """Main security manager that coordinates all security features."""
    
    def __init__(self, secret_arn: str = None):
        self.secrets_auth = AWSSecretsManagerAuth(secret_arn) if secret_arn else None
        self.rate_limiter = RateLimiter()
        self.audit_logger = AuditLogger()
        
        # Rate limit configurations by endpoint
        self.rate_limits = {
            "get_account": {"limit": 50, "window": 3600},      # 50/hour
            "query_billing": {"limit": 100, "window": 3600},   # 100/hour
            "get_subscription": {"limit": 50, "window": 3600}  # 50/hour
        }
    
    def authenticate_request(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Authenticate request and return user context."""
        if not api_key:
            return None
        
        if self.secrets_auth:
            # Use AWS Secrets Manager
            key_info = self.secrets_auth.validate_api_key(api_key)
            if not key_info:
                return None
            
            # Check expiration
            if key_info.get("expires") and time.time() > key_info["expires"]:
                return None
            
            return {
                "user_id": key_info["user_id"],
                "role": key_info["role"],
                "permissions": key_info["permissions"],
                "api_key": api_key[:8] + "..."  # Masked for logging
            }
        else:
            # No authentication configured
            return None
    
    def check_rate_limit(self, client_id: str, endpoint: str) -> Dict[str, Any]:
        """Check rate limit for client and endpoint."""
        config = self.rate_limits.get(endpoint, {"limit": 100, "window": 3600})
        return self.rate_limiter.is_allowed(
            client_id, 
            config["limit"], 
            config["window"]
        )
    
    def log_request(self, request_data: Dict[str, Any]):
        """Log API request."""
        self.audit_logger.log_request(request_data)
    
    def log_security_event(self, event_data: Dict[str, Any]):
        """Log security event."""
        self.audit_logger.log_security_event(event_data)
    
    def log_rate_limit_event(self, event_data: Dict[str, Any]):
        """Log rate limit event."""
        self.audit_logger.log_rate_limit_event(event_data)

# Global security manager instance (will be initialized with AWS secret ARN)
security_manager = None

def initialize_security_manager(secret_arn: str = None):
    """Initialize the global security manager with AWS secret ARN."""
    global security_manager
    security_manager = SecurityManager(secret_arn)
    return security_manager

def secure_endpoint(entity_type: str = 'default'):
    """Enhanced security decorator that combines all security features."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request_id = str(uuid.uuid4())
            start_time = time.time()
            
            # Extract request context based on transport mode
            import os
            
            # Get transport mode from main module
            try:
                from main import TRANSPORT_MODE
                transport_mode = TRANSPORT_MODE
            except ImportError:
                transport_mode = "stdio"  # Default fallback
            
            if transport_mode == "streamable-http":
                # HTTP mode: Try to extract from request context
                api_key = kwargs.pop("_api_key", None)
                client_ip = kwargs.pop("_client_ip", None)
                user_agent = kwargs.pop("_user_agent", None)
                
                # If no API key provided, use default
                if not api_key:
                    api_key = os.getenv("DEFAULT_API_KEY", "sk-test-abcdef1234567890")
            else:
                # stdio mode: Use defaults for MCP
                api_key = kwargs.pop("_api_key", None)
                client_ip = None
                user_agent = None
                
                # Use default API key if none provided (for Claude Desktop)
                if not api_key:
                    api_key = os.getenv("DEFAULT_API_KEY", "sk-test-abcdef1234567890")
            
            # 1. Authentication
            user_context = security_manager.authenticate_request(api_key)
            if not user_context:
                security_event_data = {
                    "request_id": request_id,
                    "event": "authentication_failed",
                    "severity": "high",
                    "api_key": api_key[:8] + "..." if api_key else "none",
                    "endpoint": func.__name__,
                    "details": {"reason": "invalid_api_key"}
                }
                
                # Add client info if available (HTTP mode)
                if transport_mode == "streamable-http" and client_ip:
                    security_event_data["client_ip"] = client_ip
                if transport_mode == "streamable-http" and user_agent:
                    security_event_data["user_agent"] = user_agent
                
                security_manager.log_security_event(security_event_data)
                return json.dumps({
                    "error": "Unauthorized",
                    "code": 401,
                    "message": "Invalid or missing API key",
                    "request_id": request_id
                })
            
            # 2. Rate Limiting
            client_id = user_context["user_id"]
            rate_limit_result = security_manager.check_rate_limit(client_id, func.__name__)
            
            if not rate_limit_result["allowed"]:
                rate_limit_event_data = {
                    "request_id": request_id,
                    "user_id": user_context["user_id"],
                    "api_key": user_context["api_key"],
                    "endpoint": func.__name__,
                    "current_count": rate_limit_result["current_count"],
                    "limit": rate_limit_result["limit"],
                    "window": rate_limit_result["window"],
                    "reset_time": rate_limit_result["reset_time"]
                }
                
                # Add client info if available (HTTP mode)
                if transport_mode == "streamable-http" and client_ip:
                    rate_limit_event_data["client_ip"] = client_ip
                if transport_mode == "streamable-http" and user_agent:
                    rate_limit_event_data["user_agent"] = user_agent
                
                security_manager.log_rate_limit_event(rate_limit_event_data)
                return json.dumps({
                    "error": "Rate limit exceeded",
                    "code": 429,
                    "message": f"Rate limit of {rate_limit_result['limit']} requests per {rate_limit_result['window']} seconds exceeded",
                    "current_count": rate_limit_result["current_count"],
                    "limit": rate_limit_result["limit"],
                    "reset_time": rate_limit_result["reset_time"],
                    "request_id": request_id
                })
            
            # 3. Call original function
            try:
                response = await func(*args, **kwargs)
                status = "success"
                
                # Parse JSON response if it's a string
                if isinstance(response, str):
                    try:
                        data = json.loads(response)
                    except json.JSONDecodeError:
                        data = response
                else:
                    data = response
                    
            except Exception as e:
                status = "error"
                api_error_event_data = {
                    "request_id": request_id,
                    "event": "api_error",
                    "severity": "high",
                    "user_id": user_context["user_id"],
                    "api_key": user_context["api_key"],
                    "endpoint": func.__name__,
                    "details": {"error": str(e)}
                }
                
                # Add client info if available (HTTP mode)
                if transport_mode == "streamable-http" and client_ip:
                    api_error_event_data["client_ip"] = client_ip
                if transport_mode == "streamable-http" and user_agent:
                    api_error_event_data["user_agent"] = user_agent
                
                security_manager.log_security_event(api_error_event_data)
                raise
            
            # 4. Apply existing security enhancements
            try:
                from utils.security_enhancer import EnhancedSecurityEnhancer
                fresh_enhancer = EnhancedSecurityEnhancer()
                secure_data = fresh_enhancer.create_structured_response(data, entity_type)
                
                # 5. Add security metadata
                secure_data["meta"]["requestId"] = request_id
                secure_data["meta"]["userId"] = user_context["user_id"]
                secure_data["meta"]["userRole"] = user_context["role"]
                secure_data["meta"]["apiKey"] = user_context["api_key"]
                secure_data["meta"]["timestamp"] = datetime.utcnow().isoformat()
                secure_data["meta"]["rateLimitInfo"] = {
                    "current_count": rate_limit_result["current_count"],
                    "limit": rate_limit_result["limit"],
                    "window": rate_limit_result["window"]
                }
                
                final_response = json.dumps(secure_data)
                
            except Exception as e:
                # Fallback to basic response if security enhancement fails
                final_response = json.dumps({
                    "llm_view": response,
                    "meta": {
                        "requestId": request_id,
                        "userId": user_context["user_id"],
                        "userRole": user_context["role"],
                        "apiKey": user_context["api_key"],
                        "timestamp": datetime.utcnow().isoformat(),
                        "securityApplied": False,
                        "error": "Security enhancement failed"
                    }
                })
            
            # 6. Log successful request
            response_time_ms = int((time.time() - start_time) * 1000)
            
            # Prepare log data based on transport mode
            log_data = {
                "request_id": request_id,
                "user_id": user_context["user_id"],
                "api_key": user_context["api_key"],
                "endpoint": func.__name__,
                "method": "MCP" if transport_mode == "stdio" else "HTTP",
                "parameters": {k: v for k, v in kwargs.items() if not k.startswith("_")},
                "response_time_ms": response_time_ms,
                "status": status
            }
            
            # Add client info if available (HTTP mode)
            if transport_mode == "streamable-http" and client_ip:
                log_data["client_ip"] = client_ip
            if transport_mode == "streamable-http" and user_agent:
                log_data["user_agent"] = user_agent
            
            security_manager.log_request(log_data)
            
            return final_response
        
        return wrapper
    return decorator
