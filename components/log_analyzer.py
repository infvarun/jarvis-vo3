import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional
import re

class LogAnalyzer:
    """Handles log data analysis and filtering operations"""
    
    def __init__(self):
        self.log_levels = ['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL']
    
    def filter_logs(self, log_data: List[Dict[str, Any]], 
                   start_time: Optional[str] = None,
                   end_time: Optional[str] = None,
                   log_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Filter log entries based on time range and log levels
        
        Args:
            log_data: List of log entry dictionaries
            start_time: Start time filter (YYYY-MM-DD HH:MM:SS format)
            end_time: End time filter (YYYY-MM-DD HH:MM:SS format)
            log_levels: List of log levels to include
            
        Returns:
            Filtered list of log entries
        """
        filtered_logs = log_data.copy()
        
        # Filter by time range
        if start_time:
            try:
                start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                filtered_logs = [
                    log for log in filtered_logs
                    if log.get('timestamp') and log['timestamp'] >= start_dt
                ]
            except ValueError:
                pass  # Invalid time format, skip filtering
        
        if end_time:
            try:
                end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
                filtered_logs = [
                    log for log in filtered_logs
                    if log.get('timestamp') and log['timestamp'] <= end_dt
                ]
            except ValueError:
                pass  # Invalid time format, skip filtering
        
        # Filter by log levels
        if log_levels:
            filtered_logs = [
                log for log in filtered_logs
                if log.get('level', '').upper() in [level.upper() for level in log_levels]
            ]
        
        return filtered_logs
    
    def group_logs_by_component(self, log_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group log entries by component/service
        
        Args:
            log_data: List of log entry dictionaries
            
        Returns:
            Dictionary mapping components to their log entries
        """
        grouped = {}
        
        for log in log_data:
            component = log.get('component', 'Unknown')
            if component not in grouped:
                grouped[component] = []
            grouped[component].append(log)
        
        return grouped
    
    def group_logs_by_level(self, log_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group log entries by log level
        
        Args:
            log_data: List of log entry dictionaries
            
        Returns:
            Dictionary mapping log levels to their entries
        """
        grouped = {}
        
        for log in log_data:
            level = log.get('level', 'Unknown').upper()
            if level not in grouped:
                grouped[level] = []
            grouped[level].append(log)
        
        return grouped
    
    def get_error_summary(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for errors and warnings
        
        Args:
            log_data: List of log entry dictionaries
            
        Returns:
            Dictionary containing error summary statistics
        """
        error_levels = ['ERROR', 'CRITICAL', 'FATAL', 'WARN', 'WARNING']
        error_logs = [log for log in log_data if log.get('level', '').upper() in error_levels]
        
        summary = {
            'total_logs': len(log_data),
            'total_errors': len(error_logs),
            'error_rate': len(error_logs) / len(log_data) * 100 if log_data else 0,
            'by_level': {},
            'by_component': {},
            'time_range': self._get_time_range(log_data)
        }
        
        # Count by level
        for level in error_levels:
            count = len([log for log in error_logs if log.get('level', '').upper() == level])
            if count > 0:
                summary['by_level'][level] = count
        
        # Count by component
        for log in error_logs:
            component = log.get('component', 'Unknown')
            summary['by_component'][component] = summary['by_component'].get(component, 0) + 1
        
        return summary
    
    def _get_time_range(self, log_data: List[Dict[str, Any]]) -> Dict[str, Optional[datetime]]:
        """
        Get the time range of log entries
        
        Args:
            log_data: List of log entry dictionaries
            
        Returns:
            Dictionary with start and end timestamps
        """
        timestamps = [log['timestamp'] for log in log_data if log.get('timestamp') is not None]
        
        if timestamps:
            return {
                'start': min(timestamps),
                'end': max(timestamps)
            }
        else:
            return {'start': None, 'end': None}
    
    def find_patterns(self, log_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find common error patterns in log data
        
        Args:
            log_data: List of log entry dictionaries
            
        Returns:
            List of pattern dictionaries
        """
        patterns = []
        error_messages = []
        
        # Extract error messages
        for log in log_data:
            if log.get('level', '').upper() in ['ERROR', 'CRITICAL', 'FATAL']:
                message = log.get('message', '')
                if message:
                    error_messages.append(message)
        
        # Find common patterns (simplified pattern matching)
        pattern_counts = {}
        for message in error_messages:
            # Extract potential patterns (remove specific values like IDs, timestamps, etc.)
            normalized = re.sub(r'\d+', 'XXX', message)  # Replace numbers
            normalized = re.sub(r'[0-9a-fA-F-]{36}', 'UUID', normalized)  # Replace UUIDs
            normalized = re.sub(r'\b\w+@\w+\.\w+\b', 'EMAIL', normalized)  # Replace emails
            
            pattern_counts[normalized] = pattern_counts.get(normalized, 0) + 1
        
        # Convert to sorted list
        for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
            if count > 1:  # Only include patterns that occur multiple times
                patterns.append({
                    'pattern': pattern,
                    'count': count,
                    'examples': [msg for msg in error_messages if self._matches_pattern(msg, pattern)][:3]
                })
        
        return patterns[:10]  # Return top 10 patterns
    
    def _matches_pattern(self, message: str, pattern: str) -> bool:
        """
        Check if a message matches a pattern
        
        Args:
            message: Original log message
            pattern: Pattern to match against
            
        Returns:
            Boolean indicating if message matches pattern
        """
        # Simple pattern matching - normalize message same way as pattern
        normalized = re.sub(r'\d+', 'XXX', message)
        normalized = re.sub(r'[0-9a-fA-F-]{36}', 'UUID', normalized)
        normalized = re.sub(r'\b\w+@\w+\.\w+\b', 'EMAIL', normalized)
        
        return normalized == pattern
