"""
Real-time Log Monitor for streaming analysis
Monitors log files and provides live analysis of user activities, transactions, and errors
"""
import os
import time
import threading
import queue
from pathlib import Path
from typing import Dict, Any, List, Optional, Generator
import streamlit as st
from datetime import datetime, timedelta
import re
import subprocess
import tempfile

from utils.logger import enterprise_logger
from utils.performance import performance_monitor
from components.ai_analyzer import AIAnalyzer

class RealtimeLogMonitor:
    """Handles real-time log file monitoring and streaming analysis"""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.log_queue = queue.Queue()
        self.current_position = 0
        self.file_path = None
        self.ai_analyzer = AIAnalyzer()
        self.activity_patterns = {
            'login': [
                r'(?i)(login|logon|authentication|sign.?in)',
                r'(?i)(user|username|userid)[:\s]+([a-zA-Z0-9_\-\.@]+)',
                r'(?i)(successful|failed|error).*(?:login|authentication)'
            ],
            'transaction': [
                r'(?i)(transaction|order|purchase|payment)',
                r'(?i)(transaction.?id|order.?id|reference)[:\s]+([a-zA-Z0-9\-]+)',
                r'(?i)(amount|total|price)[:\s]+[\$€¥]?([0-9,\.]+)',
                r'(?i)(completed|processed|failed|error).*(?:transaction|order)'
            ],
            'error': [
                r'(?i)(error|exception|failure|fatal)',
                r'(?i)(stack.?trace|caused.?by)',
                r'(?i)(timeout|connection.*failed|database.*error)',
                r'(?i)(http.*[45]\d\d|status.*[45]\d\d)'
            ],
            'performance': [
                r'(?i)(slow|timeout|performance|latency)',
                r'(?i)(response.*time|duration)[:\s]+([0-9\.]+)',
                r'(?i)(memory|cpu|disk).*(?:usage|high|low|full)'
            ]
        }
    
    def validate_log_path(self, file_path: str) -> tuple[bool, str]:
        """
        Validate if the log file path is accessible
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Handle different path formats
            if file_path.startswith('\\\\'):  # UNC path
                # For Windows UNC paths, try to access directly
                path_obj = Path(file_path)
            elif file_path.startswith('/'):  # Unix path
                path_obj = Path(file_path)
            else:
                # Relative path
                path_obj = Path(file_path)
            
            if not path_obj.exists():
                return False, f"File not found: {file_path}"
            
            if not path_obj.is_file():
                return False, f"Path is not a file: {file_path}"
            
            # Try to read the file
            try:
                with open(path_obj, 'r', encoding='utf-8') as f:
                    f.readline()  # Try to read one line
            except PermissionError:
                return False, f"Permission denied: {file_path}"
            except UnicodeDecodeError:
                # Try with different encoding
                try:
                    with open(path_obj, 'r', encoding='latin-1') as f:
                        f.readline()
                except Exception as e:
                    return False, f"Cannot read file encoding: {str(e)}"
            
            return True, f"File accessible: {path_obj.name}"
            
        except Exception as e:
            return False, f"Path validation error: {str(e)}"
    
    def get_file_end_position(self, file_path: str) -> int:
        """
        Get the current end position of the file (EOF)
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Current file size/position
        """
        try:
            return os.path.getsize(file_path)
        except Exception as e:
            enterprise_logger.log_error(e, f"Failed to get file size for {file_path}")
            return 0
    
    def extract_activity_info(self, log_line: str) -> Dict[str, Any]:
        """
        Extract key activity information from a log line
        
        Args:
            log_line: Single log line to analyze
            
        Returns:
            Dictionary containing extracted activity information
        """
        activity_info = {
            'timestamp': datetime.now().isoformat(),
            'original_line': log_line.strip(),
            'activities': [],
            'priority': 'LOW'
        }
        
        # Extract timestamp from log line
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)',
            r'(\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                activity_info['log_timestamp'] = match.group(1)
                break
        
        # Check each activity type
        for activity_type, patterns in self.activity_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, log_line)
                if matches:
                    activity_info['activities'].append({
                        'type': activity_type,
                        'pattern': pattern,
                        'matches': matches
                    })
                    
                    # Set priority based on activity type
                    if activity_type == 'error':
                        activity_info['priority'] = 'HIGH'
                    elif activity_type in ['login', 'transaction'] and activity_info['priority'] != 'HIGH':
                        activity_info['priority'] = 'MEDIUM'
        
        return activity_info
    
    def monitor_log_file(self, file_path: str, start_position: Optional[int] = None):
        """
        Monitor log file for new entries in a separate thread
        
        Args:
            file_path: Path to the log file to monitor
            start_position: Starting position in file (defaults to EOF)
        """
        try:
            if start_position is None:
                start_position = self.get_file_end_position(file_path)
            
            self.current_position = start_position
            
            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                file.seek(start_position)
                
                while self.monitoring:
                    line = file.readline()
                    
                    if line:
                        # Process new log line
                        activity_info = self.extract_activity_info(line)
                        self.log_queue.put({
                            'type': 'log_line',
                            'data': activity_info,
                            'position': file.tell()
                        })
                        self.current_position = file.tell()
                    else:
                        # No new data, wait a bit
                        time.sleep(0.5)
                        
                        # Check if file was rotated or truncated
                        current_size = os.path.getsize(file_path)
                        if current_size < self.current_position:
                            # File was truncated or rotated, restart from beginning
                            file.seek(0)
                            self.current_position = 0
                            self.log_queue.put({
                                'type': 'file_rotated',
                                'data': {'message': 'Log file rotated, monitoring from beginning'},
                                'position': 0
                            })
                            
        except Exception as e:
            error_msg = f"Monitor error: {str(e)}"
            enterprise_logger.log_error(e, error_msg)
            self.log_queue.put({
                'type': 'error',
                'data': {'error': error_msg},
                'position': self.current_position
            })
    
    def start_monitoring(self, file_path: str, start_from_end: bool = True) -> bool:
        """
        Start monitoring a log file
        
        Args:
            file_path: Path to the log file
            start_from_end: Whether to start from EOF or beginning
            
        Returns:
            Success status
        """
        try:
            if self.monitoring:
                self.stop_monitoring()
            
            # Validate file path
            is_valid, message = self.validate_log_path(file_path)
            if not is_valid:
                self.log_queue.put({
                    'type': 'error',
                    'data': {'error': message},
                    'position': 0
                })
                return False
            
            self.file_path = file_path
            self.monitoring = True
            
            # Determine start position
            start_position = self.get_file_end_position(file_path) if start_from_end else 0
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self.monitor_log_file,
                args=(file_path, start_position),
                daemon=True
            )
            self.monitor_thread.start()
            
            # Log start event
            self.log_queue.put({
                'type': 'monitoring_started',
                'data': {
                    'file_path': file_path,
                    'start_position': start_position,
                    'message': f'Started monitoring: {Path(file_path).name}'
                },
                'position': start_position
            })
            
            enterprise_logger.log_user_action(
                "REALTIME_MONITORING_STARTED",
                file_path=file_path,
                start_position=start_position
            )
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to start monitoring: {str(e)}"
            enterprise_logger.log_error(e, error_msg)
            self.log_queue.put({
                'type': 'error',
                'data': {'error': error_msg},
                'position': 0
            })
            return False
    
    def stop_monitoring(self):
        """Stop log file monitoring"""
        try:
            self.monitoring = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=2.0)
            
            # Clear the queue
            while not self.log_queue.empty():
                try:
                    self.log_queue.get_nowait()
                except queue.Empty:
                    break
            
            self.log_queue.put({
                'type': 'monitoring_stopped',
                'data': {'message': 'Log monitoring stopped'},
                'position': self.current_position
            })
            
            enterprise_logger.log_user_action("REALTIME_MONITORING_STOPPED")
            
        except Exception as e:
            enterprise_logger.log_error(e, "Failed to stop monitoring")
    
    def get_log_updates(self) -> List[Dict[str, Any]]:
        """
        Get all pending log updates from the queue
        
        Returns:
            List of log update events
        """
        updates = []
        try:
            while not self.log_queue.empty():
                try:
                    update = self.log_queue.get_nowait()
                    updates.append(update)
                except queue.Empty:
                    break
        except Exception as e:
            enterprise_logger.log_error(e, "Failed to get log updates")
        
        return updates
    
    def analyze_activity_batch(self, activities: List[Dict[str, Any]], user_context: str = "") -> Dict[str, Any]:
        """
        Analyze a batch of activities with AI
        
        Args:
            activities: List of activity information from log lines
            user_context: Additional context from user
            
        Returns:
            AI analysis results
        """
        try:
            # Prepare analysis context
            analysis_context = {
                'realtime_activities': activities,
                'user_context': user_context,
                'analysis_type': 'realtime_monitoring',
                'batch_size': len(activities),
                'time_range': {
                    'start': activities[0]['timestamp'] if activities else datetime.now().isoformat(),
                    'end': activities[-1]['timestamp'] if activities else datetime.now().isoformat()
                }
            }
            
            # Use AI analyzer
            return self.ai_analyzer.analyze_logs(analysis_context)
            
        except Exception as e:
            return {
                'error': f"Batch analysis failed: {str(e)}",
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """
        Get current monitoring statistics
        
        Returns:
            Dictionary containing monitoring stats
        """
        return {
            'is_monitoring': self.monitoring,
            'file_path': self.file_path,
            'current_position': self.current_position,
            'queue_size': self.log_queue.qsize(),
            'thread_alive': self.monitor_thread.is_alive() if self.monitor_thread else False
        }