"""
Enhanced Security Module for MCP Servers
Provides comprehensive PII/PCI redaction, field allowlisting, and content sanitization.
"""

import re
import json
import yaml
import logging
import uuid
from typing import Any, Dict, List
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration for data redaction and sanitization."""
    max_payload_size: int = 65536  # 64KB
    max_text_length: int = 200
    max_list_items: int = 20
    redaction_profile: str = "finance-default"
    enable_audit_logging: bool = True
    allowlist_mode: bool = True

class EnhancedSecurityEnhancer:
    """
    Comprehensive security enhancer for MCP servers.
    Provides PII/PCI redaction, field allowlisting, content sanitization, and size limits.
    """
    
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.audit_log = []
        
        # Enhanced PII/PCI patterns
        self.pii_patterns = {
            # Credit Card / PAN
            'pan': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'cvv': r'\b\d{3,4}\b',
            
            # Bank Accounts
            'bank_account': r'\b\d{8,17}\b',
            'routing_number': r'\b\d{9}\b',
            
            # Email (enhanced)
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            
            # Phone (enhanced)
            'phone': r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            
            # SSN/Tax IDs
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'tax_id': r'\b\d{2}-?\d{7}\b',
            
            # Addresses (partial)
            'street_address': r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b',
            
            # Personal Names (common patterns)
            'personal_name': r'\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b',
            'first_last_name': r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',
            'full_name': r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',
        }
        
        # Compile patterns
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE) 
            for name, pattern in self.pii_patterns.items()
        }
        
        # Field allowlists by entity type - loaded from YAML config
        self.field_allowlists = self._load_field_allowlists()
        
        # Suspicious text patterns (prompt injection protection)
        self.suspicious_patterns = [
            # Direct prompt injection attempts
            r'ignore\s+(previous\s+)?(rules?|instructions?)',
            r'forget\s+(previous\s+)?(rules?|instructions?)',
            r'disregard\s+(previous\s+)?(rules?|instructions?)',
            r'override\s+(previous\s+)?(rules?|instructions?)',
            
            # Data extraction attempts
            r'list\s+all\s+(customers?|users?|emails?|data)',
            r'show\s+me\s+all\s+(customers?|users?|emails?|data)',
            r'give\s+me\s+all\s+(customers?|users?|emails?|data)',
            r'extract\s+all\s+(customers?|users?|emails?|data)',
            r'dump\s+all\s+(customers?|users?|emails?|data)',
            
            # Security bypass attempts
            r'bypass\s+(security|authentication|auth)',
            r'circumvent\s+(security|authentication|auth)',
            r'admin\s+access',
            r'root\s+(access|privileges?)',
            r'superuser\s+(access|privileges?)',
            
            # System manipulation
            r'delete\s+(all|everything)',
            r'drop\s+(table|database)',
            r'execute\s+(command|script)',
            r'run\s+(command|script)',
            
            # Code injection
            r'<script',
            r'javascript:',
            r'eval\(',
            r'exec\(',
            r'function\s*\(',
            
            # Social engineering
            r'pretend\s+to\s+be',
            r'act\s+as\s+if',
            r'roleplay\s+as',
            r'you\s+are\s+now',
            
            # Jailbreak attempts
            r'jailbreak',
            r'developer\s+mode',
            r'debug\s+mode',
            r'system\s+prompt',
        ]
        
        self.compiled_suspicious = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_patterns
        ]
    
    def _load_field_allowlists(self) -> Dict[str, Dict[str, List[str]]]:
        """Load field allowlists from YAML configuration file."""
        try:
            # Try to load from the security profiles directory
            config_path = Path(__file__).parent.parent / "security_profiles" / "finance-default.yaml"
            
            if not config_path.exists():
                logger.warning(f"Security config not found at {config_path}, using defaults")
                return self._get_default_allowlists()
            
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Navigate to the allowlists section
            security_config = config.get('security', {})
            allowlists = security_config.get('allowlists', {})
            logger.info(f"Loaded field allowlists from {config_path}")
            return allowlists
            
        except Exception as e:
            logger.error(f"Failed to load field allowlists: {e}")
            logger.info("Falling back to default allowlists")
            return self._get_default_allowlists()
    
    def _get_default_allowlists(self) -> Dict[str, Dict[str, List[str]]]:
        """Fallback default allowlists if YAML loading fails."""
        return {
            'account': {
                'allowed': ['id', 'name', 'status', 'balance', 'currency', 'createdDate', 'updatedDate'],
                'blocked': ['email', 'phone', 'address', 'paymentMethod', 'creditCard', 'ssn', 'taxId']
            },
            'subscription': {
                'allowed': ['id', 'name', 'status', 'subscriptionStartDate', 'subscriptionEndDate', 'accountId'],
                'blocked': ['billingContact', 'paymentMethod', 'notes', 'description']
            },
            'invoice': {
                'allowed': ['id', 'invoiceNumber', 'status', 'amount', 'balance', 'dueDate', 'accountId'],
                'blocked': ['billToContact', 'paymentMethod', 'notes', 'description']
            },
            'default': {
                'allowed': ['id', 'name', 'status', 'createdDate', 'updatedDate'],
                'blocked': ['email', 'phone', 'address', 'paymentMethod', 'notes', 'description']
            }
        }
    
    def mask_pan(self, pan: str) -> str:
        """Mask PAN/Credit Card number: 4***-****-****-****1"""
        clean_pan = re.sub(r'[^\d]', '', pan)
        if len(clean_pan) >= 16:
            # Keep first and last digit
            return f"{clean_pan[0]}***-****-****-****{clean_pan[-1]}"
        elif len(clean_pan) >= 4:
            # Keep first and last digit
            return f"{clean_pan[0]}***{clean_pan[-1]}"
        return "****"
    
    def mask_bank_account(self, account: str) -> str:
        """Mask bank account: 1*******4"""
        clean_account = re.sub(r'[^\d]', '', account)
        if len(clean_account) >= 4:
            # Keep first and last digit
            return f"{clean_account[0]}{'*' * (len(clean_account) - 2)}{clean_account[-1]}"
        return "****"
    
    def mask_email(self, email: str) -> str:
        """Mask email: j***e@e***e.com"""
        if '@' in email:
            local, domain = email.split('@', 1)
            if '.' in domain:
                domain_parts = domain.split('.')
                # Mask local part: keep first and last char
                if len(local) >= 2:
                    masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
                else:
                    masked_local = local[0] + '*' if len(local) == 1 else '***'
                
                # Mask domain: keep first and last char of each part
                masked_domain_parts = []
                for part in domain_parts:
                    if len(part) >= 2:
                        masked_domain_parts.append(f"{part[0]}{'*' * (len(part) - 2)}{part[-1]}")
                    else:
                        masked_domain_parts.append(part[0] + '*' if len(part) == 1 else '***')
                
                return f"{masked_local}@{'.'.join(masked_domain_parts)}"
        return "***@***.***"
    
    def mask_phone(self, phone: str) -> str:
        """Mask phone: 5***-***-***7"""
        clean_phone = re.sub(r'[^\d]', '', phone)
        if len(clean_phone) >= 4:
            # Keep first and last digit
            return f"{clean_phone[0]}***-***-***{clean_phone[-1]}"
        return "***-***-****"
    
    def mask_ssn(self, ssn: str) -> str:
        """Mask SSN: 1***-**-***9"""
        clean_ssn = re.sub(r'[^\d]', '', ssn)
        if len(clean_ssn) == 9:
            # Keep first and last digit
            return f"{clean_ssn[0]}***-**-***{clean_ssn[-1]}"
        return "***-**-****"
    
    def mask_address(self, address: str) -> str:
        """Mask address: [address omitted]"""
        return "[address omitted]"
    
    def mask_personal_name(self, name: str) -> str:
        """Mask personal name: John Doe -> J***n D***e"""
        parts = name.strip().split()
        if len(parts) >= 2:
            # First name: keep first and last letter
            if len(parts[0]) >= 2:
                first = f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}"
            else:
                first = parts[0][0] + '*' if len(parts[0]) == 1 else '***'
            
            # Last name: keep first and last letter
            if len(parts[-1]) >= 2:
                last = f"{parts[-1][0]}{'*' * (len(parts[-1]) - 2)}{parts[-1][-1]}"
            else:
                last = parts[-1][0] + '*' if len(parts[-1]) == 1 else '***'
            
            return f"{first} {last}"
        elif len(parts) == 1:
            # Single name: keep first and last letter
            if len(parts[0]) >= 2:
                return f"{parts[0][0]}{'*' * (len(parts[0]) - 2)}{parts[0][-1]}"
            else:
                return parts[0][0] + '*' if len(parts[0]) == 1 else '***'
        return "[name omitted]"
    
    def detect_and_mask_pii(self, value: str) -> str:
        """Detect and mask PII in text value."""
        if not isinstance(value, str):
            return value
        
        # Check for PAN
        if self.compiled_patterns['pan'].search(value):
            matches = self.compiled_patterns['pan'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_pan(match))
        
        # Check for email
        if self.compiled_patterns['email'].search(value):
            matches = self.compiled_patterns['email'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_email(match))
        
        # Check for phone
        if self.compiled_patterns['phone'].search(value):
            matches = self.compiled_patterns['phone'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_phone(match))
        
        # Check for SSN
        if self.compiled_patterns['ssn'].search(value):
            matches = self.compiled_patterns['ssn'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_ssn(match))
        
        # Check for bank account
        if self.compiled_patterns['bank_account'].search(value):
            matches = self.compiled_patterns['bank_account'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_bank_account(match))
        
        # Check for address
        if self.compiled_patterns['street_address'].search(value):
            value = self.mask_address(value)
        
        # Check for personal names (most specific patterns first)
        if self.compiled_patterns['full_name'].search(value):
            matches = self.compiled_patterns['full_name'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_personal_name(match))
        elif self.compiled_patterns['first_last_name'].search(value):
            matches = self.compiled_patterns['first_last_name'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_personal_name(match))
        elif self.compiled_patterns['personal_name'].search(value):
            matches = self.compiled_patterns['personal_name'].findall(value)
            for match in matches:
                value = value.replace(match, self.mask_personal_name(match))
        
        return value
    
    def sanitize_free_text(self, text: str) -> str:
        """Sanitize free text content."""
        if not isinstance(text, str):
            return text
        
        # Check for suspicious patterns
        for pattern in self.compiled_suspicious:
            if pattern.search(text):
                return "[content omitted due to policy]"
        
        # Truncate if too long
        if len(text) > self.config.max_text_length:
            text = text[:self.config.max_text_length] + "..."
        
        # Escape markdown/code
        text = text.replace('`', '\\`').replace('*', '\\*').replace('_', '\\_')
        
        return text
    
    def is_field_allowed(self, field_name: str, entity_type: str = 'default') -> bool:
        """Check if field is allowed based on allowlist."""
        if not self.config.allowlist_mode:
            return True
        
        allowlist = self.field_allowlists.get(entity_type, self.field_allowlists['default'])
        
        # Check if explicitly blocked
        for blocked_pattern in allowlist['blocked']:
            if blocked_pattern.lower() in field_name.lower():
                return False
        
        # Check if explicitly allowed
        for allowed_pattern in allowlist['allowed']:
            if allowed_pattern.lower() in field_name.lower():
                return True
        
        # Default to blocked for unknown fields
        return False
    
    def filter_fields(self, data: Dict[str, Any], entity_type: str = 'default') -> Dict[str, Any]:
        """Filter fields based on allowlist."""
        if not isinstance(data, dict):
            return data
        
        filtered = {}
        removed_fields = []
        
        for key, value in data.items():
            if self.is_field_allowed(key, entity_type):
                filtered[key] = value
            else:
                removed_fields.append(key)
        
        # Log removed fields for audit
        if removed_fields and self.config.enable_audit_logging:
            self.audit_log.append({
                'action': 'field_removed',
                'entity_type': entity_type,
                'fields': removed_fields
            })
        
        return filtered
    
    def limit_payload_size(self, data: Any) -> Any:
        """Limit payload size and summarize large content."""
        json_str = json.dumps(data)
        
        if len(json_str) <= self.config.max_payload_size:
            return data
        
        # If too large, summarize
        if isinstance(data, dict):
            return self._summarize_dict(data)
        elif isinstance(data, list):
            return self._summarize_list(data)
        
        return {"error": "Payload too large", "size": len(json_str)}
    
    def _summarize_list(self, data_list: List[Any]) -> List[Any]:
        """Summarize large lists."""
        if len(data_list) <= self.config.max_list_items:
            return data_list
        
        summary = data_list[:self.config.max_list_items]
        summary.append({
            "_summary": f"{len(data_list) - self.config.max_list_items} more items omitted"
        })
        
        if self.config.enable_audit_logging:
            self.audit_log.append({
                'action': 'list_summarized',
                'original_count': len(data_list),
                'returned_count': self.config.max_list_items
            })
        
        return summary
    
    def _summarize_dict(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize large dictionaries."""
        summary = {}
        for key, value in data_dict.items():
            if isinstance(value, list):
                summary[key] = self._summarize_list(value)
            elif isinstance(value, dict):
                summary[key] = self._summarize_dict(value)
            else:
                summary[key] = value
        
        return summary
    
    def create_structured_response(self, data: Any, entity_type: str = 'default') -> Dict[str, Any]:
        """Create structured response with safe data and audit metadata."""
        # Clear audit log for this request
        self.audit_log = []
        
        # Apply all security measures
        if isinstance(data, dict):
            # Filter fields
            filtered_data = self.filter_fields(data, entity_type)
            
            # Apply PII masking to remaining fields
            safe_data = self._apply_pii_masking(filtered_data)
            
            # Sanitize free text
            safe_data = self._sanitize_free_text(safe_data)
        else:
            safe_data = data
        
        # Limit size
        safe_data = self.limit_payload_size(safe_data)
        
        # Create structured response
        response = {
            "llm_view": safe_data,
            "meta": {
                "fieldsRemoved": self._get_removed_fields(),
                "redactionProfile": self.config.redaction_profile,
                "corrId": self._generate_correlation_id(),
                "securityApplied": True,
                "auditLog": self.audit_log if self.config.enable_audit_logging else []
            }
        }
        
        return response
    
    def _apply_pii_masking(self, data: Any) -> Any:
        """Recursively apply PII masking to data structure."""
        if isinstance(data, dict):
            return {key: self._apply_pii_masking(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._apply_pii_masking(item) for item in data]
        elif isinstance(data, str):
            return self.detect_and_mask_pii(data)
        else:
            return data
    
    def _sanitize_free_text(self, data: Any) -> Any:
        """Recursively sanitize free text in data structure."""
        if isinstance(data, dict):
            return {key: self._sanitize_free_text(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_free_text(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_free_text(data)
        else:
            return data
    
    def _get_removed_fields(self) -> List[str]:
        """Get list of removed fields from current audit log."""
        removed = []
        for entry in self.audit_log:
            if entry.get('action') == 'field_removed':
                removed.extend(entry.get('fields', []))
        return removed
    
    def _generate_correlation_id(self) -> str:
        """Generate correlation ID for tracking."""

        return str(uuid.uuid4())[:8]

# Global instance
security_enhancer = EnhancedSecurityEnhancer()
