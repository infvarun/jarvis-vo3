"""
Enterprise Configuration Settings
"""
import os
from typing import Dict, List, Optional

class Config:
    """Application configuration management"""
    
    # Security Settings
    MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '100'))
    ALLOWED_FILE_EXTENSIONS = os.getenv('ALLOWED_FILE_EXTENSIONS', 'txt,log,csv').split(',')
    SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', '30'))
    
    # AI Settings
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o')
    OPENAI_TEMPERATURE = float(os.getenv('OPENAI_TEMPERATURE', '0.3'))
    MAX_TOKENS = int(os.getenv('MAX_TOKENS', '4000'))
    
    # Database Settings
    DB_CONNECTION_TIMEOUT = int(os.getenv('DB_CONNECTION_TIMEOUT', '30'))
    DB_QUERY_TIMEOUT = int(os.getenv('DB_QUERY_TIMEOUT', '300'))
    MAX_DB_ROWS = int(os.getenv('MAX_DB_ROWS', '10000'))
    
    # Logging Settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))
    
    # Performance Settings
    CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '3600'))
    MAX_CONCURRENT_ANALYSES = int(os.getenv('MAX_CONCURRENT_ANALYSES', '5'))
    
    @classmethod
    def validate_config(cls) -> Dict[str, bool]:
        """Validate configuration settings"""
        validation_results = {}
        
        # Check required environment variables
        required_vars = ['OPENAI_API_KEY']
        for var in required_vars:
            validation_results[var] = os.getenv(var) is not None
            
        return validation_results
    
    @classmethod
    def get_security_headers(cls) -> Dict[str, str]:
        """Get security headers for the application"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }