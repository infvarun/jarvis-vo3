"""
Simplified War Room Agent for reliable operation
"""
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.tools import DuckDuckGoSearchRun

from utils.logger import enterprise_logger
from utils.performance import monitor_ai_analysis


class SimpleWarRoomAgent:
    """Simplified intelligent agent for log analysis and troubleshooting"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
            temperature=0.3
        )
        
        # Web search tool for StackOverflow and technical documentation
        try:
            self.search_tool = DuckDuckGoSearchRun()
        except Exception as e:
            enterprise_logger.log_error(e, "Web search tool initialization failed")
            self.search_tool = None
        
        # Session memory
        self.conversation_history = []
    
    def _prepare_context_summary(self, context: Dict[str, Any]) -> str:
        """Prepare a summary of available context for the LLM"""
        summary_parts = []
        
        logs = context.get("logs", [])
        if logs:
            summary_parts.append(f"Log Data: {len(logs)} entries")
            
            # Add sample of recent errors
            error_logs = [log for log in logs[-100:] if log.get("level") in ["ERROR", "CRITICAL", "FATAL"]]
            if error_logs:
                summary_parts.append(f"Recent Errors: {len(error_logs)} error entries found")
                sample_errors = error_logs[:3]
                for i, error in enumerate(sample_errors, 1):
                    summary_parts.append(f"Error {i}: {error.get('message', 'No message')[:100]}...")
        
        if context.get("database_results"):
            db_results = context["database_results"]
            if isinstance(db_results, list):
                summary_parts.append(f"Database Results: {len(db_results)} rows")
            else:
                summary_parts.append("Database Results: Available")
        
        if context.get("xml_context"):
            summary_parts.append("XML Context: Configuration data available")
        
        return "\n".join(summary_parts) if summary_parts else "No context data available"
    
    def _perform_initial_analysis(self, user_query: str, context: Dict[str, Any]) -> str:
        """Perform initial analysis using available context"""
        context_summary = self._prepare_context_summary(context)
        
        system_prompt = """You are a Site Reliability Engineer expert analyzing system logs and troubleshooting issues.

Available context:
{context_summary}

Your task:
1. Analyze the user's question in relation to the available data
2. Provide insights based on logs, database results, and XML context
3. Identify patterns, errors, and potential solutions
4. Be specific and actionable in your recommendations

Focus on practical troubleshooting and root cause analysis."""

        messages = [
            SystemMessage(content=system_prompt.format(context_summary=context_summary)),
            HumanMessage(content=f"Question: {user_query}")
        ]
        
        try:
            response = self.llm.invoke(messages)
            return response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            enterprise_logger.log_error(e, "Initial analysis failed")
            return f"Error during initial analysis: {str(e)}"
    
    def _perform_thinking_reflection(self, user_query: str, initial_response: str) -> tuple:
        """Self-reflection and thinking process to improve response quality"""
        thinking_prompt = f"""Review this initial analysis and determine if it needs improvement:

User Question: {user_query}
Initial Analysis: {initial_response}

Think step by step:
1. Is the analysis complete and accurate?
2. Are there gaps in the information that web search could fill?
3. Would additional technical documentation or StackOverflow solutions help?
4. What specific search terms would be most helpful?

Provide your thinking process and decide if web search is needed (YES/NO)."""
        
        try:
            thinking_response = self.llm.invoke([HumanMessage(content=thinking_prompt)])
            thinking_content = thinking_response.content if hasattr(thinking_response, 'content') else str(thinking_response)
            
            # Determine if search is needed based on thinking
            search_indicators = ["YES", "web search", "stackoverflow", "documentation", "additional information"]
            search_needed = any(indicator.lower() in thinking_content.lower() for indicator in search_indicators)
            
            return thinking_content, search_needed
        except Exception as e:
            enterprise_logger.log_error(e, "Thinking reflection failed")
            return f"Thinking process error: {str(e)}", False
    
    def _perform_web_search(self, user_query: str) -> Optional[str]:
        """Perform web search for additional technical information"""
        if not self.search_tool:
            return "Web search tool not available"
        
        search_query = f"site:stackoverflow.com {user_query} troubleshooting solution"
        
        try:
            search_results = self.search_tool.run(search_query)
            enterprise_logger.log_user_action("WEB_SEARCH_PERFORMED", 
                                            query=search_query, 
                                            results_length=len(search_results))
            return search_results
        except Exception as e:
            enterprise_logger.log_error(e, "Web search failed")
            return f"Search error: {str(e)}"
    
    def _synthesize_response(self, user_query: str, initial_response: str, thinking: str, search_results: Optional[str]) -> str:
        """Synthesize all information into final response"""
        synthesis_prompt = f"""Synthesize all available information into a comprehensive, actionable response:

User Question: {user_query}
Initial Analysis: {initial_response}
Thinking Process: {thinking}
Web Search Results: {search_results or "No web search performed"}

Provide a final, comprehensive answer that:
1. Directly addresses the user's question
2. Uses insights from the log analysis
3. Incorporates relevant web search findings if available
4. Provides actionable recommendations
5. Includes specific code fixes or configuration changes if applicable

Format the response clearly with sections for different types of information."""
        
        try:
            final_response = self.llm.invoke([HumanMessage(content=synthesis_prompt)])
            return final_response.content if hasattr(final_response, 'content') else str(final_response)
        except Exception as e:
            enterprise_logger.log_error(e, "Synthesis failed")
            return f"Synthesis error: {str(e)}"
    
    @monitor_ai_analysis
    def chat(self, user_message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Main chat interface for the War Room agent"""
        
        # Add user message to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
            "timestamp": datetime.now().isoformat()
        })
        
        try:
            # Step 1: Initial analysis
            initial_response = self._perform_initial_analysis(user_message, context)
            
            # Step 2: Thinking and reflection
            thinking, search_needed = self._perform_thinking_reflection(user_message, initial_response)
            
            # Step 3: Web search if needed
            search_results = None
            if search_needed:
                search_results = self._perform_web_search(user_message)
            
            # Step 4: Synthesize final response
            final_response = self._synthesize_response(user_message, initial_response, thinking, search_results)
            
            # Prepare response
            formatted_response = {
                "response": final_response,
                "thinking_process": thinking,
                "used_web_search": bool(search_results),
                "timestamp": datetime.now().isoformat(),
                "error": False
            }
            
            # Add to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": formatted_response["response"],
                "thinking": thinking,
                "used_web_search": bool(search_results),
                "timestamp": formatted_response["timestamp"]
            })
            
            return formatted_response
            
        except Exception as e:
            enterprise_logger.log_error(e, "War Room agent chat failed")
            error_response = {
                "response": f"I encountered an error processing your request: {str(e)}",
                "thinking_process": "Error occurred during processing",
                "used_web_search": False,
                "timestamp": datetime.now().isoformat(),
                "error": True
            }
            
            self.conversation_history.append({
                "role": "assistant",
                "content": error_response["response"],
                "timestamp": error_response["timestamp"],
                "error": True
            })
            
            return error_response
    
    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get the current conversation history"""
        return self.conversation_history
    
    def clear_conversation(self):
        """Clear the conversation history"""
        self.conversation_history = []
        enterprise_logger.log_user_action("WAR_ROOM_CONVERSATION_CLEARED")