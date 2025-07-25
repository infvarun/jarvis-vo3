"""
Enterprise logging configuration
"""
import logging
import os
from datetime import datetime
from pathlib import Path

class EnterpriseLogger:
    """Centralized logging for enterprise applications"""
    
    def __init__(self, name: str = "log_analysis_tool"):
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure logger with enterprise standards"""
        if self.logger.handlers:
            return  # Already configured
            
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Set log level
        log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.logger.setLevel(getattr(logging, log_level))
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        
        # File handler for detailed logs
        file_handler = logging.FileHandler(
            log_dir / f"app_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        console_handler.setLevel(logging.WARNING)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_user_action(self, action: str, user_id: str = "anonymous", **kwargs):
        """Log user actions for audit trail"""
        self.logger.info(f"USER_ACTION: {action} | User: {user_id} | Details: {kwargs}")
    
    def log_security_event(self, event: str, severity: str = "WARNING", **kwargs):
        """Log security-related events"""
        log_method = getattr(self.logger, severity.lower(), self.logger.warning)
        log_method(f"SECURITY_EVENT: {event} | Details: {kwargs}")
    
    def log_performance(self, operation: str, duration: float, **kwargs):
        """Log performance metrics"""
        self.logger.info(f"PERFORMANCE: {operation} | Duration: {duration:.2f}s | Details: {kwargs}")
    
    def log_error(self, error: Exception, context: str = "", **kwargs):
        """Log errors with full context"""
        self.logger.error(f"ERROR: {context} | {str(error)} | Details: {kwargs}", exc_info=True)

# Global logger instance
enterprise_logger = EnterpriseLogger()