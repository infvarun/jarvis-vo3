import streamlit as st
import re
from datetime import datetime
from typing import List, Dict, Any
from utils.log_parser import LogParser

class FileHandler:
    """Handles file upload and processing operations"""
    
    def __init__(self):
        self.log_parser = LogParser()
    
    def process_log_file(self, uploaded_file) -> List[Dict[str, Any]]:
        """
        Process an uploaded log file and extract structured log entries
        
        Args:
            uploaded_file: Streamlit uploaded file object
            
        Returns:
            List of dictionaries containing parsed log entries
        """
        try:
            # Read file content
            content = uploaded_file.read()
            
            # Try to decode as UTF-8, fallback to latin-1 if needed
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                text_content = content.decode('latin-1')
            
            # Parse log entries
            log_entries = self.log_parser.parse_log_text(text_content, uploaded_file.name)
            
            return log_entries
            
        except Exception as e:
            raise Exception(f"Failed to process log file: {str(e)}")
    
    def validate_file_size(self, uploaded_file, max_size_mb: int = 50) -> bool:
        """
        Validate that uploaded file is within size limits
        
        Args:
            uploaded_file: Streamlit uploaded file object
            max_size_mb: Maximum file size in MB
            
        Returns:
            Boolean indicating if file size is valid
        """
        file_size_mb = uploaded_file.size / (1024 * 1024)
        return file_size_mb <= max_size_mb
    
    def get_file_info(self, uploaded_file) -> Dict[str, Any]:
        """
        Get metadata about uploaded file
        
        Args:
            uploaded_file: Streamlit uploaded file object
            
        Returns:
            Dictionary containing file metadata
        """
        return {
            'name': uploaded_file.name,
            'size_bytes': uploaded_file.size,
            'size_mb': round(uploaded_file.size / (1024 * 1024), 2),
            'type': uploaded_file.type
        }
