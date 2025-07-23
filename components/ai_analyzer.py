import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import pandas as pd

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

class AIAnalyzer:
    """Handles AI-powered log analysis using LangChain and OpenAI"""
    
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        self.llm = ChatOpenAI(
            model="gpt-4o",  # Using the newest OpenAI model
            api_key=api_key if api_key else "",
            temperature=0.3
        )
    
    def analyze_logs(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform AI-powered analysis of logs with optional database and XML context
        
        Args:
            context: Dictionary containing logs, database results, and XML context
            
        Returns:
            Dictionary containing structured analysis results
        """
        try:
            # Prepare the analysis prompt
            prompt = self._build_analysis_prompt(context)
            
            # Create messages for LangChain
            messages = [
                SystemMessage(content=self._get_system_prompt()),
                HumanMessage(content=prompt)
            ]
            
            # Call LangChain LLM
            response = self.llm.invoke(messages)
            
            # Parse response - ensure we have content before parsing
            response_content = response.content if response.content else "{}"
            if isinstance(response_content, str):
                analysis_result = json.loads(response_content)
            else:
                analysis_result = {"error": "Invalid response format from AI model"}
            
            # Add metadata
            analysis_result['analysis_timestamp'] = datetime.now().isoformat()
            analysis_result['model_used'] = "gpt-4o"
            
            return analysis_result
            
        except Exception as e:
            return {
                'error': f"AI analysis failed: {str(e)}",
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for the AI analyst
        
        Returns:
            System prompt string
        """
        return """You are a senior site reliability engineer with extensive experience in system troubleshooting and log analysis. 

Your task is to analyze system/application logs, identify errors, warnings, anomalies, and potential root causes of failure. You should group related log entries, highlight timestamps, components, and affected services, summarize the impact, and suggest corrective actions.

Always respond with a valid JSON object containing the following structure:
{
    "summary": "Executive summary of findings",
    "error_categories": [
        {
            "category": "Category name",
            "severity": "HIGH|MEDIUM|LOW",
            "count": number,
            "description": "Description of the error category",
            "examples": ["example log entries"],
            "affected_components": ["component names"],
            "time_pattern": "Description of when these errors occur"
        }
    ],
    "affected_services": [
        {
            "service": "Service name",
            "impact": "Description of impact",
            "error_count": number,
            "first_occurrence": "timestamp",
            "last_occurrence": "timestamp"
        }
    ],
    "timeline": "Chronological analysis of events",
    "root_causes": [
        {
            "cause": "Root cause description",
            "evidence": ["Supporting evidence from logs"],
            "confidence": "HIGH|MEDIUM|LOW"
        }
    ],
    "recommendations": [
        "Specific actionable recommendations"
    ],
    "database_insights": "Analysis of database context if provided",
    "xml_context_insights": "Analysis of XML context if provided"
}

Focus on actionable insights and be specific about timestamps, error patterns, and remediation steps."""
    
    def _build_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """
        Build the analysis prompt with all available context
        
        Args:
            context: Dictionary containing logs, database results, and XML context
            
        Returns:
            Formatted prompt string
        """
        prompt_parts = []
        
        # Add log data
        logs = context.get('logs', [])
        if logs:
            prompt_parts.append("## LOG DATA")
            prompt_parts.append(f"Total log entries: {len(logs)}")
            
            # Group logs by level for better organization
            log_levels = {}
            for log in logs:
                level = log.get('level', 'UNKNOWN').upper()
                if level not in log_levels:
                    log_levels[level] = []
                log_levels[level].append(log)
            
            for level, level_logs in log_levels.items():
                if level in ['ERROR', 'CRITICAL', 'FATAL', 'WARN', 'WARNING']:
                    prompt_parts.append(f"\n### {level} LOGS ({len(level_logs)} entries)")
                    for log in level_logs[:20]:  # Limit to first 20 entries per level
                        timestamp = log.get('timestamp', 'Unknown time')
                        component = log.get('component', 'Unknown component')
                        message = log.get('message', 'No message')
                        prompt_parts.append(f"[{timestamp}] [{component}] {message}")
            
            # Add sample of other logs
            other_logs = [log for log in logs if log.get('level', '').upper() not in ['ERROR', 'CRITICAL', 'FATAL', 'WARN', 'WARNING']]
            if other_logs:
                prompt_parts.append(f"\n### OTHER LOGS (sample of {min(10, len(other_logs))} entries)")
                for log in other_logs[:10]:
                    timestamp = log.get('timestamp', 'Unknown time')
                    level = log.get('level', 'Unknown level')
                    component = log.get('component', 'Unknown component')
                    message = log.get('message', 'No message')
                    prompt_parts.append(f"[{timestamp}] [{level}] [{component}] {message}")
        
        # Add database context
        db_data = context.get('database_results')
        if db_data is not None and not db_data.empty:
            prompt_parts.append("\n## DATABASE CONTEXT")
            prompt_parts.append("The following database query results provide additional context:")
            prompt_parts.append(f"Rows returned: {len(db_data)}")
            prompt_parts.append("Sample data:")
            prompt_parts.append(db_data.head(10).to_string(index=False))
            
            if len(db_data) > 10:
                prompt_parts.append(f"... and {len(db_data) - 10} more rows")
        
        # Add XML context
        xml_context = context.get('xml_context')
        if xml_context:
            prompt_parts.append("\n## XML CONTEXT FILES")
            for xml_file in xml_context:
                prompt_parts.append(f"\n### XML File: {xml_file['filename']}")
                # Limit XML content to prevent token overflow
                content = xml_file['content']
                if len(content) > 2000:
                    content = content[:2000] + "\n... (truncated)"
                prompt_parts.append(content)
        
        # Add analysis instructions
        prompt_parts.append("\n## ANALYSIS REQUEST")
        prompt_parts.append("Please analyze the above log data and any provided context to:")
        prompt_parts.append("1. Identify errors, warnings, and anomalies")
        prompt_parts.append("2. Group related log entries and identify patterns")
        prompt_parts.append("3. Determine root causes and affected services")
        prompt_parts.append("4. Provide timeline analysis of events")
        prompt_parts.append("5. Suggest specific corrective actions")
        
        if db_data is not None:
            prompt_parts.append("6. Correlate log events with database data where relevant")
        
        if xml_context:
            prompt_parts.append("7. Use XML context to better understand system configuration and behavior")
        
        return "\n".join(prompt_parts)
    
    def _format_logs_for_analysis(self, logs: List[Dict[str, Any]]) -> str:
        """
        Format log entries for AI analysis
        
        Args:
            logs: List of log entry dictionaries
            
        Returns:
            Formatted string representation of logs
        """
        formatted_logs = []
        
        for log in logs:
            timestamp = log.get('timestamp', 'Unknown time')
            level = log.get('level', 'Unknown level')
            component = log.get('component', 'Unknown component')
            message = log.get('message', 'No message')
            filename = log.get('filename', '')
            
            log_line = f"[{timestamp}] [{level}] [{component}]"
            if filename:
                log_line += f" [{filename}]"
            log_line += f" {message}"
            
            formatted_logs.append(log_line)
        
        return "\n".join(formatted_logs)
    
    def validate_openai_api_key(self) -> bool:
        """
        Validate that OpenAI API key is available and working
        
        Returns:
            Boolean indicating if API key is valid
        """
        try:
            # Try a simple API call using LangChain
            messages = [HumanMessage(content="Hello")]
            response = self.llm.invoke(messages)
            return response.content is not None
        except Exception:
            return False
