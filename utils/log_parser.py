import re
from datetime import datetime
from typing import List, Dict, Any, Optional

class LogParser:
    """Utility class for parsing log files and extracting structured data"""
    
    def __init__(self):
        # Common log patterns
        self.timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # 2024-01-01 12:00:00
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',  # 2024/01/01 12:00:00
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # 01/01/2024 12:00:00
            r'\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}',  # 01-01-2024 12:00:00
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',        # Jan 01 12:00:00
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO format
        ]
        
        self.level_patterns = [
            r'\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|TRACE)\b',
        ]
        
        # Common component/service patterns
        self.component_patterns = [
            r'\[([^\]]+)\]',  # [ComponentName]
            r'(\w+)\.(\w+):',  # service.component:
            r'(\w+\.\w+\.\w+)',  # package.class.method
        ]
    
    def parse_log_text(self, text_content: str, filename: str) -> List[Dict[str, Any]]:
        """
        Parse log text content and extract structured log entries
        
        Args:
            text_content: Raw log file content
            filename: Original filename for reference
            
        Returns:
            List of dictionaries containing parsed log entries
        """
        log_entries = []
        lines = text_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Parse individual log entry
            log_entry = self._parse_log_line(line, filename, line_num)
            if log_entry:
                log_entries.append(log_entry)
        
        return log_entries
    
    def _parse_log_line(self, line: str, filename: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line into structured data
        
        Args:
            line: Log line text
            filename: Source filename
            line_num: Line number in file
            
        Returns:
            Dictionary containing parsed log entry or None if parsing fails
        """
        try:
            # Extract timestamp
            timestamp = self._extract_timestamp(line)
            
            # Extract log level
            level = self._extract_log_level(line)
            
            # Extract component/service
            component = self._extract_component(line)
            
            # Extract message (remainder after removing timestamp, level, component)
            message = self._extract_message(line, timestamp, level, component)
            
            return {
                'timestamp': timestamp,
                'level': level,
                'component': component,
                'message': message,
                'filename': filename,
                'line_number': line_num,
                'raw_line': line
            }
            
        except Exception:
            # If parsing fails, return basic entry
            return {
                'timestamp': None,
                'level': 'UNKNOWN',
                'component': 'Unknown',
                'message': line,
                'filename': filename,
                'line_number': line_num,
                'raw_line': line
            }
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """
        Extract timestamp from log line
        
        Args:
            line: Log line text
            
        Returns:
            Parsed datetime object or None if no timestamp found
        """
        for pattern in self.timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group()
                return self._parse_timestamp(timestamp_str)
        
        return None
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse timestamp string into datetime object
        
        Args:
            timestamp_str: Timestamp string
            
        Returns:
            Parsed datetime object or None if parsing fails
        """
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%m-%d-%Y %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Handle special case for syslog format (Jan 01 12:00:00)
        try:
            # Add current year for syslog format
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, '%Y %b %d %H:%M:%S')
        except ValueError:
            pass
        
        return None
    
    def _extract_log_level(self, line: str) -> str:
        """
        Extract log level from log line
        
        Args:
            line: Log line text
            
        Returns:
            Log level string or 'UNKNOWN' if not found
        """
        for pattern in self.level_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).upper()
        
        return 'UNKNOWN'
    
    def _extract_component(self, line: str) -> str:
        """
        Extract component/service name from log line
        
        Args:
            line: Log line text
            
        Returns:
            Component name or 'Unknown' if not found
        """
        # Try bracketed components first [ComponentName]
        bracket_match = re.search(r'\[([^\]]+)\]', line)
        if bracket_match:
            component = bracket_match.group(1)
            # Filter out timestamp-like and level-like values
            if not re.match(r'^\d{4}-\d{2}-\d{2}', component) and component.upper() not in ['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL']:
                return component
        
        # Try package.class pattern
        package_match = re.search(r'(\w+\.\w+\.\w+)', line)
        if package_match:
            return package_match.group(1)
        
        # Try service.component: pattern
        service_match = re.search(r'(\w+)\.(\w+):', line)
        if service_match:
            return f"{service_match.group(1)}.{service_match.group(2)}"
        
        return 'Unknown'
    
    def _extract_message(self, line: str, timestamp: Optional[datetime], 
                        level: str, component: str) -> str:
        """
        Extract log message by removing timestamp, level, and component
        
        Args:
            line: Original log line
            timestamp: Extracted timestamp
            level: Extracted log level
            component: Extracted component
            
        Returns:
            Cleaned log message
        """
        message = line
        
        # Remove timestamp
        if timestamp:
            for pattern in self.timestamp_patterns:
                message = re.sub(pattern, '', message, count=1)
        
        # Remove log level
        if level != 'UNKNOWN':
            message = re.sub(rf'\b{level}\b', '', message, count=1, flags=re.IGNORECASE)
        
        # Remove component brackets
        if component != 'Unknown':
            message = re.sub(rf'\[{re.escape(component)}\]', '', message, count=1)
        
        # Clean up extra whitespace and common separators
        message = re.sub(r'^[\s\-:]+', '', message)
        message = re.sub(r'[\s]+', ' ', message)
        
        return message.strip()
    
    def validate_log_format(self, line: str) -> bool:
        """
        Validate if a line appears to be a valid log entry
        
        Args:
            line: Log line to validate
            
        Returns:
            Boolean indicating if line appears to be a valid log entry
        """
        line = line.strip()
        if not line:
            return False
        
        # Check for timestamp
        has_timestamp = any(re.search(pattern, line) for pattern in self.timestamp_patterns)
        
        # Check for log level
        has_level = any(re.search(pattern, line, re.IGNORECASE) for pattern in self.level_patterns)
        
        # A valid log line should have at least a timestamp or log level
        return has_timestamp or has_level
