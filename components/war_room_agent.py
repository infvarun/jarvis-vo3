"""
War Room Agentic Chat using LangGraph
Intelligent agent for log analysis, database queries, and web search
"""
import json
import os
from typing import Dict, List, Any, Optional
try:
    from typing_extensions import TypedDict
except ImportError:
    from typing import TypedDict
from datetime import datetime

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_community.tools import DuckDuckGoSearchRun
from langgraph.graph import StateGraph, END


from utils.logger import enterprise_logger
from utils.performance import monitor_ai_analysis


class AgentState(TypedDict):
    """State for the War Room agent"""
    messages: List[Dict[str, Any]]
    context: Dict[str, Any]
    thinking: str
    search_needed: bool
    search_results: Optional[str]
    initial_response: str
    final_response: str
    formatted_response: Dict[str, Any]
    iteration_count: int


class WarRoomAgent:
    """Intelligent agent for log analysis and troubleshooting"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
            temperature=0.3
        )
        
        # Web search tool for StackOverflow and technical documentation
        self.search_tool = DuckDuckGoSearchRun()
        
        # Build the agent graph
        self.graph = self._build_graph()
        
        # Session memory
        self.conversation_history = []
        
    def _build_graph(self):
        """Build the LangGraph agent workflow"""
        
        # Define the graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("input_processing", self._process_input)
        workflow.add_node("context_gathering", self._gather_context)
        workflow.add_node("initial_analysis", self._initial_analysis)
        workflow.add_node("thinking_reflection", self._thinking_reflection)
        workflow.add_node("web_search", self._web_search)
        workflow.add_node("synthesis", self._synthesis)
        workflow.add_node("response_formatting", self._format_response)
        
        # Define the flow
        workflow.set_entry_point("input_processing")
        
        workflow.add_edge("input_processing", "context_gathering")
        workflow.add_edge("context_gathering", "initial_analysis")
        workflow.add_edge("initial_analysis", "thinking_reflection")
        
        # Conditional edge based on search need
        workflow.add_conditional_edges(
            "thinking_reflection",
            self._should_search,
            {
                "search": "web_search",
                "no_search": "synthesis"
            }
        )
        
        workflow.add_edge("web_search", "synthesis")
        workflow.add_edge("synthesis", "response_formatting")
        workflow.add_edge("response_formatting", END)
        
        return workflow.compile()
    
    def _process_input(self, state: AgentState) -> AgentState:
        """Process user input and extract intent"""
        enterprise_logger.log_user_action("WAR_ROOM_QUERY", query_preview=state["messages"][-1]["content"][:100])
        
        state["iteration_count"] = state.get("iteration_count", 0) + 1
        return state
    
    def _gather_context(self, state: AgentState) -> AgentState:
        """Gather relevant context from logs, database, and XML"""
        context = state["context"]
        
        # Analyze what context is available
        available_context = []
        if context.get("logs"):
            available_context.append(f"Log entries: {len(context['logs'])} entries")
        if context.get("database_results"):
            available_context.append("Database query results available")
        if context.get("xml_context"):
            available_context.append("XML configuration context available")
        
        # Add context summary to state
        state["context"]["available_summary"] = available_context
        return state
    
    def _initial_analysis(self, state: AgentState) -> AgentState:
        """Perform initial analysis using available context"""
        user_query = state["messages"][-1]["content"]
        context = state["context"]
        
        # Prepare context summary for LLM
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
            state["initial_response"] = response.content
            enterprise_logger.log_performance("initial_analysis", 1.0, success=True)
        except Exception as e:
            enterprise_logger.log_error(e, "Initial analysis failed")
            state["initial_response"] = f"Error during initial analysis: {str(e)}"
        
        return state
    
    def _thinking_reflection(self, state: AgentState) -> AgentState:
        """Self-reflection and thinking process to improve response quality"""
        initial_response = state.get("initial_response", "")
        user_query = state["messages"][-1]["content"]
        
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
            state["thinking"] = thinking_content
            
            # Determine if search is needed based on thinking
            search_indicators = ["YES", "web search", "stackoverflow", "documentation", "additional information"]
            state["search_needed"] = any(indicator.lower() in thinking_content.lower() 
                                       for indicator in search_indicators)
            
            enterprise_logger.log_performance("thinking_reflection", 1.0, 
                                            search_needed=state["search_needed"])
        except Exception as e:
            enterprise_logger.log_error(e, "Thinking reflection failed")
            state["thinking"] = f"Thinking process error: {str(e)}"
            state["search_needed"] = False
        
        return state
    
    def _should_search(self, state: AgentState) -> str:
        """Determine if web search is needed"""
        return "search" if state.get("search_needed", False) else "no_search"
    
    def _web_search(self, state: AgentState) -> AgentState:
        """Perform web search for additional technical information"""
        user_query = state["messages"][-1]["content"]
        thinking = state.get("thinking", "")
        
        # Extract search terms from thinking or use user query
        search_query = f"site:stackoverflow.com {user_query} troubleshooting solution"
        
        try:
            search_results = self.search_tool.run(search_query)
            state["search_results"] = search_results
            
            enterprise_logger.log_user_action("WEB_SEARCH_PERFORMED", 
                                            query=search_query, 
                                            results_length=len(search_results))
        except Exception as e:
            enterprise_logger.log_error(e, "Web search failed")
            state["search_results"] = f"Search error: {str(e)}"
        
        return state
    
    def _synthesis(self, state: AgentState) -> AgentState:
        """Synthesize all information into final response"""
        user_query = state["messages"][-1]["content"]
        initial_response = state.get("initial_response", "")
        thinking = state.get("thinking", "")
        search_results = state.get("search_results", "")
        context = state["context"]
        
        synthesis_prompt = f"""Synthesize all available information into a comprehensive, actionable response:

User Question: {user_query}
Initial Analysis: {initial_response}
Thinking Process: {thinking}
Web Search Results: {search_results}

Available Context: {self._prepare_context_summary(context)}

Provide a final, comprehensive answer that:
1. Directly addresses the user's question
2. Uses insights from the log analysis
3. Incorporates relevant web search findings
4. Provides actionable recommendations
5. Includes specific code fixes or configuration changes if applicable

Format the response clearly with sections for different types of information."""
        
        try:
            final_response = self.llm.invoke([HumanMessage(content=synthesis_prompt)])
            final_content = final_response.content if hasattr(final_response, 'content') else str(final_response)
            state["final_response"] = final_content
            enterprise_logger.log_performance("synthesis", 1.0, success=True)
        except Exception as e:
            enterprise_logger.log_error(e, "Synthesis failed")
            state["final_response"] = f"Synthesis error: {str(e)}"
        
        return state
    
    def _format_response(self, state: AgentState) -> AgentState:
        """Format the final response for display"""
        final_response = state.get("final_response", "")
        thinking = state.get("thinking", "")
        search_results = state.get("search_results", "")
        
        # Add metadata about the response process
        formatted_response = {
            "response": final_response,
            "thinking_process": thinking,
            "used_web_search": bool(search_results),
            "timestamp": datetime.now().isoformat(),
            "iteration_count": state.get("iteration_count", 1)
        }
        
        state["formatted_response"] = formatted_response
        return state
    
    def _prepare_context_summary(self, context: Dict[str, Any]) -> str:
        """Prepare a summary of available context for the LLM"""
        summary_parts = []
        
        if context.get("logs"):
            logs = context["logs"]
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
            summary_parts.append(f"XML Context: Configuration data available")
        
        return "\n".join(summary_parts) if summary_parts else "No context data available"
    
    @monitor_ai_analysis
    def chat(self, user_message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Main chat interface for the War Room agent"""
        
        # Add user message to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
            "timestamp": datetime.now().isoformat()
        })
        
        # Prepare initial state
        initial_state = {
            "messages": [{"role": "user", "content": user_message}],
            "context": context,
            "thinking": "",
            "search_needed": False,
            "search_results": None,
            "initial_response": "",
            "final_response": "",
            "formatted_response": {},
            "iteration_count": 0
        }
        
        try:
            # Run the agent workflow
            result = self.graph.invoke(initial_state)
            
            # Extract formatted response
            formatted_response = result.get("formatted_response", {})
            
            # Add to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": formatted_response.get("response", "No response generated"),
                "thinking": formatted_response.get("thinking_process", ""),
                "used_web_search": formatted_response.get("used_web_search", False),
                "timestamp": formatted_response.get("timestamp", datetime.now().isoformat())
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