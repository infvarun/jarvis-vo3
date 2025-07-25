"""
Enterprise security utilities
"""
import hashlib
import hmac
import os
import time
from typing import Dict, List, Optional, Tuple
import streamlit as st
from utils.logger import enterprise_logger

class SecurityManager:
    """Handles security-related operations"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY', 'default-secret-key-change-in-production')
        self.failed_attempts = {}
        self.max_attempts = 5
        self.lockout_duration = 300  # 5 minutes
    
    def validate_file_upload(self, uploaded_file) -> Tuple[bool, str]:
        """Validate uploaded files for security"""
        if not uploaded_file:
            return False, "No file uploaded"
        
        # Check file size
        max_size = 100 * 1024 * 1024  # 100MB
        if uploaded_file.size > max_size:
            enterprise_logger.log_security_event(
                "FILE_SIZE_EXCEEDED", 
                filename=uploaded_file.name,
                size=uploaded_file.size
            )
            return False, f"File size exceeds {max_size // (1024*1024)}MB limit"
        
        # Check file extension
        allowed_extensions = ['.txt', '.log', '.csv']
        file_ext = os.path.splitext(uploaded_file.name)[1].lower()
        if file_ext not in allowed_extensions:
            enterprise_logger.log_security_event(
                "INVALID_FILE_EXTENSION",
                filename=uploaded_file.name,
                extension=file_ext
            )
            return False, f"File type {file_ext} not allowed"
        
        # Basic content validation
        try:
            content_sample = uploaded_file.read(1024).decode('utf-8', errors='ignore')
            uploaded_file.seek(0)  # Reset file pointer
            
            # Check for suspicious patterns
            suspicious_patterns = ['<script', '<?php', '#!/bin', 'powershell']
            for pattern in suspicious_patterns:
                if pattern.lower() in content_sample.lower():
                    enterprise_logger.log_security_event(
                        "SUSPICIOUS_FILE_CONTENT",
                        filename=uploaded_file.name,
                        pattern=pattern
                    )
                    return False, "File contains suspicious content"
                    
        except Exception as e:
            enterprise_logger.log_error(e, "File validation error")
            return False, "Unable to validate file content"
        
        return True, "File validation passed"
    
    def sanitize_sql_query(self, query: str) -> Tuple[bool, str, str]:
        """Sanitize and validate SQL queries"""
        if not query or not query.strip():
            return False, "", "Empty query"
        
        query = query.strip()
        
        # Dangerous SQL patterns
        dangerous_patterns = [
            'drop table', 'delete from', 'truncate table', 'alter table',
            'create table', 'insert into', 'update set', 'exec ', 'execute',
            'xp_cmdshell', 'sp_configure', '--', '/*', '*/'
        ]
        
        query_lower = query.lower()
        for pattern in dangerous_patterns:
            if pattern in query_lower:
                enterprise_logger.log_security_event(
                    "DANGEROUS_SQL_PATTERN",
                    pattern=pattern,
                    query_preview=query[:100]
                )
                return False, "", f"Query contains dangerous pattern: {pattern}"
        
        # Only allow SELECT statements
        if not query_lower.strip().startswith('select'):
            enterprise_logger.log_security_event(
                "NON_SELECT_QUERY",
                query_preview=query[:100]
            )
            return False, "", "Only SELECT queries are allowed"
        
        return True, query, "Query validation passed"
    
    def generate_session_token(self) -> str:
        """Generate secure session token"""
        timestamp = str(time.time())
        random_data = os.urandom(32)
        token_data = f"{timestamp}:{random_data.hex()}"
        
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{token_data}:{signature}"
    
    def validate_session_token(self, token: str) -> bool:
        """Validate session token"""
        try:
            parts = token.split(':')
            if len(parts) != 3:
                return False
            
            timestamp, random_data, signature = parts
            token_data = f"{timestamp}:{random_data}"
            
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
            
            # Check if token is not expired (24 hours)
            token_age = time.time() - float(timestamp)
            if token_age > 86400:  # 24 hours
                return False
            
            return True
        except Exception:
            return False
    
    def log_access_attempt(self, user_identifier: str, success: bool):
        """Log access attempts for monitoring"""
        enterprise_logger.log_user_action(
            "ACCESS_ATTEMPT",
            user_id=user_identifier,
            success=success,
            timestamp=time.time()
        )

# Global security manager
security_manager = SecurityManager()