import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import pandas as pd

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

class AIAnalyzer:
    """Handles AI-powered log analysis using LangChain and OpenAI"""
    
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        # Set environment variable for LangChain to pick up
        os.environ["OPENAI_API_KEY"] = api_key
        
        self.llm = ChatOpenAI(
            model="gpt-4o",  # Using the newest OpenAI model
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
                # Clean up response content - remove markdown code blocks if present
                clean_content = response_content.strip()
                
                # Try to extract JSON from markdown code blocks
                if "```json" in clean_content:
                    json_start = clean_content.find("```json") + 7
                    json_end = clean_content.find("```", json_start)
                    if json_end != -1:
                        clean_content = clean_content[json_start:json_end].strip()
                elif "```" in clean_content:
                    # Handle generic code blocks
                    json_start = clean_content.find("```") + 3
                    json_end = clean_content.find("```", json_start)
                    if json_end != -1:
                        clean_content = clean_content[json_start:json_end].strip()
                
                try:
                    analysis_result = json.loads(clean_content)
                except json.JSONDecodeError as e:
                    analysis_result = {
                        "error": f"Failed to parse AI response as JSON: {str(e)}",
                        "raw_response": response_content[:500] + "..." if len(response_content) > 500 else response_content
                    }
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

IMPORTANT: Respond ONLY with a valid JSON object. Do not include any markdown formatting, explanations, or text outside the JSON. The response must start with '{' and end with '}'.

Use this exact JSON structure:
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
            context: Dictionary containing logs, database results, XML context, and optional problem statement
            
        Returns:
            Formatted prompt string
        """
        prompt_parts = []
        
        # Add problem statement for focused analysis if provided
        if context.get('problem_statement'):
            problem = context['problem_statement']
            prompt_parts.append("## PROBLEM STATEMENT (PRIORITY FOCUS)")
            prompt_parts.append(f"**Issue to investigate:** {problem}")
            prompt_parts.append("\n**INSTRUCTION:** Focus your analysis specifically on log entries and patterns related to the above problem statement. Use semantic analysis to identify relevant logs, even if they don't contain exact keywords. Prioritize findings that could explain or relate to this specific issue.")
        
        # Add log data with semantic filtering if problem statement exists
        logs = context.get('logs', [])
        if logs:
            if context.get('problem_statement'):
                # Apply semantic filtering for relevant logs
                filtered_logs = self._semantic_filter_logs(logs, context['problem_statement'])
                prompt_parts.append(f"\n## FILTERED LOG DATA (PROBLEM-FOCUSED)")
                prompt_parts.append(f"Showing {len(filtered_logs)} most relevant entries out of {len(logs)} total, filtered for the problem statement.")
                logs_to_analyze = filtered_logs
            else:
                prompt_parts.append("\n## LOG DATA")
                prompt_parts.append(f"Total log entries: {len(logs)}")
                logs_to_analyze = logs
            
            # Group logs by level for better organization
            log_levels = {}
            for log in logs_to_analyze:
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
            other_logs = [log for log in logs_to_analyze if log.get('level', '').upper() not in ['ERROR', 'CRITICAL', 'FATAL', 'WARN', 'WARNING']]
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
    
    def _semantic_filter_logs(self, logs: List[Dict[str, Any]], problem_statement: str) -> List[Dict[str, Any]]:
        """
        Filter logs based on semantic relevance to the problem statement
        
        Args:
            logs: List of log entries
            problem_statement: The problem description to filter against
            
        Returns:
            List of filtered log entries most relevant to the problem
        """
        # Keywords extraction and scoring
        problem_keywords = self._extract_keywords(problem_statement.lower())
        
        scored_logs = []
        for log_entry in logs:
            score = self._calculate_relevance_score(log_entry, problem_keywords, problem_statement)
            if score > 0:  # Only include logs with some relevance
                scored_logs.append((score, log_entry))
        
        # Sort by relevance score (highest first) and return top entries
        scored_logs.sort(key=lambda x: x[0], reverse=True)
        
        # Return top 200 most relevant logs, or all if fewer than 200
        max_relevant_logs = min(200, len(scored_logs))
        return [log_entry for _, log_entry in scored_logs[:max_relevant_logs]]
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract important keywords from problem statement"""
        import re
        
        # Remove common stopwords but keep technical terms
        stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'this', 'that', 'these', 'those'}
        
        # Split into words and filter
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = [word for word in words if len(word) > 2 and word not in stopwords]
        
        return keywords
    
    def _calculate_relevance_score(self, log_entry: Dict[str, Any], keywords: List[str], problem_statement: str) -> float:
        """Calculate relevance score for a log entry"""
        score = 0.0
        message = log_entry.get('message', '').lower()
        component = log_entry.get('component', '').lower()
        level = log_entry.get('level', '').lower()
        
        # Exact keyword matches in message (highest weight)
        for keyword in keywords:
            if keyword in message:
                score += 3.0
            if keyword in component:
                score += 2.0
        
        # Error level relevance
        if level in ['error', 'fatal', 'critical'] and any(word in problem_statement.lower() for word in ['error', 'crash', 'fail', 'timeout', 'exception']):
            score += 2.0
        elif level in ['warn', 'warning'] and 'warning' in problem_statement.lower():
            score += 1.5
        
        # Pattern matching for common issues
        if 'timeout' in problem_statement.lower() and any(word in message for word in ['timeout', 'time out', 'timed out']):
            score += 4.0
        if 'memory' in problem_statement.lower() and any(word in message for word in ['memory', 'heap', 'oom', 'outofmemory']):
            score += 4.0
        if 'connection' in problem_statement.lower() and any(word in message for word in ['connection', 'connect', 'socket', 'network']):
            score += 4.0
        if 'database' in problem_statement.lower() and any(word in message for word in ['database', 'db', 'sql', 'query']):
            score += 4.0
        if any(word in problem_statement.lower() for word in ['crash', 'exception', 'error']) and any(word in message for word in ['exception', 'error', 'failed', 'crash']):
            score += 4.0
        
        return score
    
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
