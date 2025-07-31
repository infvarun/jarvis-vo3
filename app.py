import streamlit as st
import pandas as pd
import os
import hashlib
import json
import base64
import time
from datetime import datetime, timedelta
from components.file_handler import FileHandler
from components.database_handler import DatabaseHandler
from components.xml_parser import XMLParser
from components.log_analyzer import LogAnalyzer
from components.ai_analyzer import AIAnalyzer
from components.image_ocr_handler import ImageOCRHandler
from components.realtime_monitor import RealtimeLogMonitor

# Enterprise utilities
from config.settings import Config
from utils.logger import enterprise_logger
from utils.security import security_manager
from utils.performance import performance_monitor, monitor_ai_analysis, monitor_file_processing
from utils.cache import enterprise_cache

# War Room Agent
from components.simple_war_room_agent import SimpleWarRoomAgent

# Configure page
st.set_page_config(
    page_title="Log Analysis Tool",
    page_icon="🔍",
    layout="wide"
)

def main():
    # Initialize enterprise features
    initialize_enterprise_features()
    
    # Simple purple/blue accent styling
    st.markdown("""
    <style>
    /* Primary buttons with gradient */
    .stButton > button[kind="primary"] {
        background: linear-gradient(45deg, #6366f1, #8b5cf6);
        border: none;
        color: white;
    }
    
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(45deg, #4f46e5, #7c3aed);
    }
    
    /* Headers with gradient text */
    h1 {
        background: linear-gradient(45deg, #6366f1, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    /* Tab styling with rounded corners and padding */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        padding: 4px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 12px;
        padding: 8px 16px;
        margin: 0 2px;
        transition: all 0.2s ease;
        border: 1px solid #e5e7eb;
        background: white;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: #f9fafb;
        border-color: #d1d5db;
    }
    
    /* Active tabs */
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(45deg, #6366f1, #8b5cf6);
        color: white;
        border: 1px solid transparent;
        box-shadow: 0 2px 4px rgba(99, 102, 241, 0.2);
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div style="display: flex; align-items: center; margin-bottom: 1rem;">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" style="margin-right: 12px;">
            <rect x="3" y="3" width="7" height="7" rx="1" fill="url(#gradient1)"/>
            <rect x="14" y="3" width="7" height="7" rx="1" fill="url(#gradient1)"/>
            <rect x="14" y="14" width="7" height="7" rx="1" fill="url(#gradient1)"/>
            <rect x="3" y="14" width="7" height="7" rx="1" fill="url(#gradient1)"/>
            <defs>
                <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#6366f1"/>
                    <stop offset="100%" style="stop-color:#8b5cf6"/>
                </linearGradient>
            </defs>
        </svg>
        <h1 style="margin: 0; background: linear-gradient(45deg, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">Log Analysis Tool</h1>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("**Intelligent troubleshooting insights using AI-powered analysis**")
    
    # Initialize session state
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'log_data' not in st.session_state:
        st.session_state.log_data = None
    if 'db_data' not in st.session_state:
        st.session_state.db_data = None
    if 'xml_context' not in st.session_state:
        st.session_state.xml_context = None
    if 'problem_statement' not in st.session_state:
        st.session_state.problem_statement = None
    if 'ocr_results' not in st.session_state:
        st.session_state.ocr_results = None
    if 'ocr_analysis' not in st.session_state:
        st.session_state.ocr_analysis = None
    if 'realtime_monitor' not in st.session_state:
        st.session_state.realtime_monitor = RealtimeLogMonitor()
    if 'live_activities' not in st.session_state:
        st.session_state.live_activities = []
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False

    # Create tabs with custom HTML icons
    st.markdown("""
    <style>
    .tab-icon {
        width: 20px;
        height: 20px;
        display: inline-block;
        margin-right: 8px;
        vertical-align: middle;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📁 File Upload", 
        "🗃️ Database Query", 
        "⚙️ Analysis", 
        "📊 Results",
        "🚨 War Room",
        "📷 Image OCR",
        "📡 Live Monitor"
    ])
    
    with tab1:
        handle_file_uploads()
    
    with tab2:
        handle_database_query()
    
    with tab3:
        handle_analysis()
    
    with tab4:
        display_results()
    
    with tab5:
        handle_war_room()
    
    with tab6:
        handle_image_ocr()
    
    with tab7:
        handle_realtime_monitoring()

def handle_file_uploads():
    st.header("File Upload")
    
    # Problem Statement Section (Top Priority)
    st.subheader("🎯 Problem Statement (Optional)")
    problem_statement = st.text_area(
        "Describe the specific issue you're investigating:",
        height=120,
        placeholder="Example: 'Application crashes during user login process' or 'Database connection timeouts in production' or 'Memory leaks in microservice deployment'...",
        help="Providing a problem statement helps narrow down the AI analysis to focus on relevant log patterns and issues. This enables semantic search-based filtering to find the most relevant log entries.",
        key="problem_statement_input"
    )
    
    if problem_statement and problem_statement.strip():
        st.session_state.problem_statement = problem_statement.strip()
        st.success("🎯 Problem statement captured - analysis will be focused on this issue")
    elif problem_statement == "":
        st.session_state.problem_statement = None
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📁 Log Files")
        log_files = st.file_uploader(
            "Upload log files (txt, log)",
            type=['txt', 'log'],
            accept_multiple_files=True,
            key="log_files"
        )
        
        if log_files:
            file_handler = FileHandler()
            log_data = []
            
            for file in log_files:
                try:
                    content = file_handler.process_log_file(file)
                    log_data.extend(content)
                    st.success(f"✅ Loaded {file.name} ({len(content)} entries)")
                except Exception as e:
                    st.error(f"❌ Error processing {file.name}: {str(e)}")
            
            if log_data:
                st.session_state.log_data = log_data
                st.info(f"📊 Total log entries loaded: {len(log_data)}")
                
                # Show semantic filtering info if problem statement exists
                if st.session_state.problem_statement:
                    st.info(f"🔍 Analysis will be focused on: '{st.session_state.problem_statement[:100]}{'...' if len(st.session_state.problem_statement) > 100 else ''}'")
    
    with col2:
        st.subheader("📄 XML Context Files (Optional)")
        xml_files = st.file_uploader(
            "Upload XML context files (up to 2)",
            type=['xml'],
            accept_multiple_files=True,
            key="xml_files"
        )
        
        if xml_files:
            if len(xml_files) > 2:
                st.warning("⚠️ Only the first 2 XML files will be processed")
                xml_files = xml_files[:2]
            
            xml_parser = XMLParser()
            xml_context = []
            
            for file in xml_files:
                try:
                    content = xml_parser.parse_xml_file(file)
                    xml_context.append({
                        'filename': file.name,
                        'content': content
                    })
                    st.success(f"✅ Parsed {file.name}")
                except Exception as e:
                    st.error(f"❌ Error parsing {file.name}: {str(e)}")
            
            if xml_context:
                st.session_state.xml_context = xml_context

def handle_database_query():
    st.header("Database Query (Optional)")
    
    with st.expander("Database Connection", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            server = st.text_input("Server", value="localhost")
            database = st.text_input("Database", value="")
            
        with col2:
            username = st.text_input("Username", value="")
            password = st.text_input("Password", type="password", value="")
    
    query = st.text_area(
        "SQL Query",
        height=150,
        placeholder="Enter your SQL Server query here..."
    )
    
    if st.button("Execute Query", type="primary"):
        if not all([server, database, username, password, query]):
            st.error("❌ Please fill in all connection details and provide a query")
            return
        
        try:
            with st.spinner("Executing query..."):
                db_handler = DatabaseHandler()
                results = db_handler.execute_query(
                    server=server,
                    database=database,
                    username=username,
                    password=password,
                    query=query
                )
                
                if results is not None and not results.empty:
                    st.session_state.db_data = results
                    st.success(f"✅ Query executed successfully! Retrieved {len(results)} rows")
                    st.dataframe(results, use_container_width=True)
                else:
                    st.info("Query executed but returned no data")
                    
        except Exception as e:
            st.error(f"❌ Database error: {str(e)}")

def handle_analysis():
    st.header("Log Analysis")
    
    if not st.session_state.log_data:
        st.warning("⚠️ Please upload log files first")
        return
    
    # Show analysis options and results side by side
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Analysis Options")
        
        # Time filters
        st.write("**Time Range Filter**")
        
        # Enable/disable time filtering
        use_time_filter = st.checkbox("Filter by time range", value=False, key="use_time_filter")
        
        start_time = None
        end_time = None
        
        if use_time_filter:
            col_start, col_end = st.columns(2)
            
            with col_start:
                start_date = st.date_input(
                    "Start Date",
                    value=datetime.now().date() - timedelta(days=1),
                    help="Select the start date for filtering",
                    key="start_date_filter"
                )
                start_time_input = st.time_input(
                    "Start Time",
                    value=datetime.now().time().replace(hour=0, minute=0, second=0),
                    help="Select the start time",
                    key="start_time_input_filter"
                )
                # Combine date and time
                start_time = datetime.combine(start_date, start_time_input).strftime("%Y-%m-%d %H:%M:%S")
            
            with col_end:
                end_date = st.date_input(
                    "End Date", 
                    value=datetime.now().date(),
                    help="Select the end date for filtering",
                    key="end_date_filter"
                )
                end_time_input = st.time_input(
                    "End Time",
                    value=datetime.now().time().replace(hour=23, minute=59, second=59),
                    help="Select the end time",
                    key="end_time_input_filter"
                )
                # Combine date and time
                end_time = datetime.combine(end_date, end_time_input).strftime("%Y-%m-%d %H:%M:%S")
        
        # Log level filter
        st.write("**Log Level Filter**")
        log_level_filter = st.multiselect(
            "Select levels to analyze",
            options=['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'],
            default=['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL'],
            key="log_level_filter"
        )
        
        # Analysis button
        if st.button("🚀 Start AI Analysis", type="primary", use_container_width=True):
            try:
                with st.spinner("Analyzing logs with AI..."):
                    # Check if API key is available first
                    api_key = os.getenv("OPENAI_API_KEY")
                    if not api_key:
                        st.error("🔐 OpenAI API key not found. Please set the OPENAI_API_KEY environment variable in your Replit secrets.")
                        st.info("💡 Go to the Secrets tab in Replit and add OPENAI_API_KEY with your OpenAI API key.")
                        return
                    
                    log_analyzer = LogAnalyzer()
                    
                    # Filter logs
                    filtered_logs = log_analyzer.filter_logs(
                        st.session_state.log_data,
                        start_time=start_time if start_time else None,
                        end_time=end_time if end_time else None,
                        log_levels=log_level_filter
                    )
                    
                    # Prepare context
                    context = {
                        'logs': filtered_logs,
                        'database_results': st.session_state.db_data,
                        'xml_context': st.session_state.xml_context,
                        'problem_statement': st.session_state.problem_statement
                    }
                    
                    # Use enhanced AI analysis with caching
                    analysis_results = enhanced_ai_analysis(context)
                    st.session_state.analysis_results = analysis_results
                    
                    st.success("✅ Analysis completed!")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"❌ Analysis error: {str(e)}")
        
        # Show data summary
        if st.session_state.log_data:
            st.write("**Data Summary**")
            st.info(f"📈 Total log entries: {len(st.session_state.log_data)}")
            
            if st.session_state.db_data is not None:
                st.info(f"💾 Database rows: {len(st.session_state.db_data)}")
            
            if st.session_state.xml_context:
                st.info(f"📄 XML files: {len(st.session_state.xml_context)}")
    
    with col2:
        st.subheader("Analysis Results")
        
        if st.session_state.analysis_results:
            display_analysis_results()
        else:
            st.info("📋 Results will appear here after running analysis")

def display_analysis_results():
    """Display analysis results in a formatted way"""
    results = st.session_state.analysis_results
    
    if 'error' in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    # Create tabs for different result sections
    result_tabs = st.tabs(["📄 Summary", "🔴 Errors", "💡 Recommendations", "📊 Details", "⬇️ Export"])
    
    with result_tabs[0]:  # Summary
        if 'summary' in results:
            st.markdown("### Executive Summary")
            st.info(results['summary'])
        
        # Key metrics
        if 'error_categories' in results:
            col1, col2, col3 = st.columns(3)
            
            total_errors = sum(cat.get('count', 0) for cat in results['error_categories'])
            high_severity = sum(1 for cat in results['error_categories'] if cat.get('severity') == 'HIGH')
            
            with col1:
                st.metric("Total Errors", total_errors)
            with col2:
                st.metric("High Severity Issues", high_severity)
            with col3:
                affected_services = len(results.get('affected_services', []))
                st.metric("Affected Services", affected_services)
    
    with result_tabs[1]:  # Errors
        if 'error_categories' in results:
            st.markdown("### Error Categories")
            
            for i, category in enumerate(results['error_categories']):
                severity = category.get('severity', 'UNKNOWN')
                count = category.get('count', 0)
                category_name = category.get('category', 'Unknown')
                
                # Color code by severity
                if severity == 'HIGH':
                    st.error(f"**🔴 {category_name}** - {count} occurrences")
                elif severity == 'MEDIUM':
                    st.warning(f"**🟡 {category_name}** - {count} occurrences")
                else:
                    st.info(f"**🔵 {category_name}** - {count} occurrences")
                
                with st.expander(f"Details for {category_name}"):
                    st.write(f"**Description**: {category.get('description', 'No description')}")
                    
                    if category.get('affected_components'):
                        st.write("**Affected Components**:")
                        for comp in category['affected_components']:
                            st.write(f"- {comp}")
                    
                    if category.get('time_pattern'):
                        st.write(f"**Time Pattern**: {category['time_pattern']}")
                    
                    if category.get('examples'):
                        st.write("**Example Log Entries**:")
                        for example in category['examples'][:3]:
                            st.code(example, language='text')
        
        # Timeline if available
        if 'timeline' in results:
            st.markdown("### Timeline Analysis")
            st.write(results['timeline'])
    
    with result_tabs[2]:  # Recommendations
        if 'recommendations' in results:
            st.markdown("### Action Items")
            
            for i, rec in enumerate(results['recommendations'], 1):
                st.markdown(f"**{i}.** {rec}")
                st.markdown("---")
        
        # Root causes
        if 'root_causes' in results:
            st.markdown("### Root Cause Analysis")
            
            for cause in results['root_causes']:
                confidence = cause.get('confidence', 'UNKNOWN')
                
                if confidence == 'HIGH':
                    st.success(f"**High Confidence**: {cause.get('cause', 'Unknown cause')}")
                elif confidence == 'MEDIUM':
                    st.warning(f"**Medium Confidence**: {cause.get('cause', 'Unknown cause')}")
                else:
                    st.info(f"**Low Confidence**: {cause.get('cause', 'Unknown cause')}")
                
                if cause.get('evidence'):
                    with st.expander("Supporting Evidence"):
                        for evidence in cause['evidence']:
                            st.write(f"- {evidence}")
    
    with result_tabs[3]:  # Details
        # Affected services table
        if 'affected_services' in results:
            st.markdown("### Affected Services")
            services_df = pd.DataFrame(results['affected_services'])
            st.dataframe(services_df, use_container_width=True)
        
        # Additional context sections
        col1, col2 = st.columns(2)
        
        with col1:
            if st.session_state.db_data is not None:
                st.markdown("### Database Context")
                st.write("Query results were included in analysis:")
                st.dataframe(st.session_state.db_data.head(5), use_container_width=True)
                if len(st.session_state.db_data) > 5:
                    st.caption(f"Showing first 5 of {len(st.session_state.db_data)} rows")
        
        with col2:
            if st.session_state.xml_context:
                st.markdown("### XML Context")
                for xml_file in st.session_state.xml_context:
                    with st.expander(f"📄 {xml_file['filename']}"):
                        content = xml_file['content']
                        if len(content) > 500:
                            st.text(content[:500] + "\n... (truncated)")
                        else:
                            st.text(content)
        
        # Analysis metadata
        if 'analysis_timestamp' in results:
            st.markdown("### Analysis Metadata")
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Analysis Time**: {results['analysis_timestamp']}")
            with col2:
                st.write(f"**AI Model**: {results.get('model_used', 'Unknown')}")
    
    with result_tabs[4]:  # Export
        st.markdown("### Export Analysis Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Text Report**")
            st.write("Comprehensive report in readable format")
            
            export_text = generate_text_report(results)
            st.download_button(
                label="📄 Download Text Report",
                data=export_text,
                file_name=f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )
        
        with col2:
            st.markdown("**JSON Data**")
            st.write("Raw analysis data for further processing")
            
            import json
            export_json = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="📊 Download JSON Data",
                data=export_json,
                file_name=f"log_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )

def display_results():
    st.header("Analysis Results Archive")
    
    if not st.session_state.analysis_results:
        st.info("No analysis results available. Please run the analysis first.")
        return
    
    st.write("View detailed analysis results in the **Analysis** tab for better formatting and organization.")
    
    # Simple display for backward compatibility
    results = st.session_state.analysis_results
    
    if 'summary' in results:
        st.subheader("Summary")
        st.write(results['summary'])
    
    if 'error_categories' in results:
        st.subheader("Error Overview")
        for category in results['error_categories']:
            st.write(f"- **{category.get('category', 'Unknown')}**: {category.get('count', 0)} occurrences ({category.get('severity', 'Unknown')} severity)")



def generate_text_report(results):
    """Generate a text report from analysis results"""
    report = []
    report.append("LOG ANALYSIS REPORT")
    report.append("=" * 50)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    if 'summary' in results:
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 20)
        report.append(results['summary'])
        report.append("")
    
    if 'error_categories' in results:
        report.append("ERROR CATEGORIES")
        report.append("-" * 20)
        for category in results['error_categories']:
            report.append(f"Category: {category.get('category', 'Unknown')}")
            report.append(f"Count: {category.get('count', 0)}")
            report.append(f"Severity: {category.get('severity', 'Unknown')}")
            report.append(f"Description: {category.get('description', 'No description')}")
            report.append("")
    
    if 'recommendations' in results:
        report.append("RECOMMENDATIONS")
        report.append("-" * 20)
        for i, rec in enumerate(results['recommendations'], 1):
            report.append(f"{i}. {rec}")
        report.append("")
    
    return "\n".join(report)

def initialize_enterprise_features():
    """Initialize enterprise-grade features"""
    # Validate configuration
    config_validation = Config.validate_config()
    
    # Log application startup
    enterprise_logger.log_user_action("APPLICATION_STARTUP")
    
    # Clear expired cache
    enterprise_cache.clear_expired_cache()
    
    # Initialize session security
    if 'session_token' not in st.session_state:
        st.session_state.session_token = security_manager.generate_session_token()
    
    # Validate session
    if not security_manager.validate_session_token(st.session_state.session_token):
        st.session_state.session_token = security_manager.generate_session_token()
        enterprise_logger.log_security_event("SESSION_RENEWED")
    
    # Initialize War Room agent
    if 'war_room_agent' not in st.session_state:
        st.session_state.war_room_agent = SimpleWarRoomAgent()



@monitor_file_processing
def enhanced_file_upload_handler(uploaded_files):
    """Enhanced file upload with security and caching"""
    processed_files = []
    
    for uploaded_file in uploaded_files:
        # Security validation
        is_valid, message = security_manager.validate_file_upload(uploaded_file)
        if not is_valid:
            st.error(f"Security validation failed for {uploaded_file.name}: {message}")
            continue
        
        # Generate file hash for caching
        file_content = uploaded_file.read()
        file_hash = hashlib.md5(file_content).hexdigest()
        
        # Check cache first
        cached_result = enterprise_cache.get_file_processing_cache(file_hash)
        if cached_result:
            st.success(f"📦 Using cached data for {uploaded_file.name}")
            processed_files.append(cached_result)
            continue
        
        # Process file
        uploaded_file.seek(0)  # Reset file pointer
        file_handler = FileHandler()
        
        try:
            log_data = file_handler.process_log_file(uploaded_file)
            
            result = {
                'filename': uploaded_file.name,
                'data': log_data,
                'hash': file_hash,
                'processed_at': datetime.now().isoformat()
            }
            
            # Cache the result
            enterprise_cache.set_file_processing_cache(file_hash, result)
            processed_files.append(result)
            
            enterprise_logger.log_user_action(
                "FILE_PROCESSED",
                filename=uploaded_file.name,
                size=len(file_content),
                entries=len(log_data) if log_data else 0
            )
            
        except Exception as e:
            enterprise_logger.log_error(e, f"File processing failed for {uploaded_file.name}")
            st.error(f"Processing failed for {uploaded_file.name}: {str(e)}")
    
    return processed_files

@monitor_ai_analysis
def enhanced_ai_analysis(context):
    """Enhanced AI analysis with caching and monitoring"""
    # Generate context hash for caching
    context_str = str(sorted(context.items()))
    context_hash = hashlib.md5(context_str.encode()).hexdigest()
    
    model_params = {
        'model': Config.OPENAI_MODEL,
        'temperature': Config.OPENAI_TEMPERATURE,
        'max_tokens': Config.MAX_TOKENS
    }
    
    # Check cache first
    cached_result = enterprise_cache.get_ai_analysis_cache(context_hash, model_params)
    if cached_result:
        st.success("🚀 Using cached AI analysis results")
        return cached_result
    
    # Perform AI analysis
    ai_analyzer = AIAnalyzer()
    result = ai_analyzer.analyze_logs(context)
    
    # Cache successful results
    if 'error' not in result:
        enterprise_cache.set_ai_analysis_cache(context_hash, model_params, result)
        
        enterprise_logger.log_user_action(
            "AI_ANALYSIS_COMPLETED",
            context_hash=context_hash[:12],
            model=Config.OPENAI_MODEL,
            log_entries=len(context.get('logs', [])),
            has_db_data=context.get('database_results') is not None,
            has_xml_context=context.get('xml_context') is not None
        )
    
    return result

def handle_war_room():
    """Handle War Room agentic chat interface"""
    st.markdown("### 🚨 War Room - Intelligent Troubleshooting Chat")
    st.markdown("**Chat with an AI agent that can analyze your logs, query databases, and search for solutions**")
    
    # Check if API key is available
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.error("🔐 OpenAI API key required for War Room. Please set OPENAI_API_KEY in your Replit secrets.")
        st.info("💡 Go to the Secrets tab in Replit and add OPENAI_API_KEY with your OpenAI API key.")
        return
    
    # Initialize chat history if not exists
    if 'war_room_messages' not in st.session_state:
        st.session_state.war_room_messages = []
    
    # Problem statement display (if available)
    if st.session_state.get('problem_statement'):
        st.info(f"🎯 **Active Problem Statement:** {st.session_state.problem_statement}")
        st.write("*The AI agent will focus its analysis on this specific issue.*")
    
    # Context panel
    with st.expander("📊 Available Context", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            log_data = st.session_state.get('log_data', [])
            logs_status = "✅" if log_data else "❌"
            log_count = len(log_data) if log_data else 0
            st.write(f"{logs_status} **Log Files**")
            if log_count > 0:
                st.write(f"└ {log_count:,} entries available")
            else:
                st.write("└ No log data loaded")
        
        with col2:
            db_status = "✅" if st.session_state.get('db_data') else "❌"
            st.write(f"{db_status} **Database Results**")
            if st.session_state.get('db_data'):
                db_count = len(st.session_state.db_data) if isinstance(st.session_state.db_data, list) else 1
                st.write(f"└ {db_count} result(s) available")
            else:
                st.write("└ No database results")
        
        with col3:
            xml_status = "✅" if st.session_state.get('xml_context') else "❌"
            st.write(f"{xml_status} **XML Context**")
            if st.session_state.get('xml_context'):
                st.write("└ Configuration data available")
            else:
                st.write("└ No XML context loaded")
    
    # Chat interface
    st.markdown("---")
    
    # Display chat history
    if st.session_state.war_room_messages:
        st.markdown("### 💬 Conversation History")
        
        for message in st.session_state.war_room_messages:
            if message["role"] == "user":
                with st.chat_message("user"):
                    st.write(message["content"])
            else:
                with st.chat_message("assistant"):
                    # Show thinking process if available
                    if message.get("thinking") and message["thinking"].strip():
                        with st.expander("💭 Agent Thinking Process", expanded=False):
                            st.write(message["thinking"])
                    
                    # Show if web search was used
                    if message.get("used_web_search"):
                        st.info("🔍 Used web search for additional technical information")
                    
                    # Show main response
                    st.write(message["content"])
                    
                    # Show timestamp
                    if message.get("timestamp"):
                        st.caption(f"⏰ {message['timestamp']}")
    
    # Input area
    st.markdown("### 💬 Ask the Agent")
    
    # Quick suggestion buttons
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔍 Analyze Errors"):
            suggested_query = "What are the main errors in the logs and how can I fix them?"
            st.session_state.suggested_query = suggested_query
    
    with col2:
        if st.button("📊 Performance Issues"):
            suggested_query = "Are there any performance issues or bottlenecks in the system?"
            st.session_state.suggested_query = suggested_query
    
    with col3:
        if st.button("🔧 Root Cause Analysis"):
            suggested_query = "What is the root cause of the recent failures?"
            st.session_state.suggested_query = suggested_query
    
    with col4:
        if st.button("💡 Recommendations"):
            suggested_query = "What are your recommendations to improve system stability?"
            st.session_state.suggested_query = suggested_query
    
    # Initialize message sent flag
    if 'message_sent' not in st.session_state:
        st.session_state.message_sent = False
    
    # Reset input value if message was just sent
    input_value = ""
    if st.session_state.get('suggested_query'):
        input_value = st.session_state.suggested_query
        # Clear suggested query after using
        del st.session_state.suggested_query
    elif st.session_state.message_sent:
        input_value = ""
        st.session_state.message_sent = False
    
    # Chat input
    user_input = st.text_area(
        "Your question:",
        value=input_value,
        placeholder="Ask about logs, errors, performance issues, or troubleshooting steps...",
        height=100,
        key="war_room_input_area"
    )
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        send_clicked = st.button("🚀 Send Message", type="primary", use_container_width=True)
        
    # Process the message if button is clicked and there's input
    if send_clicked and user_input and user_input.strip():
        # Add user message to history
        st.session_state.war_room_messages.append({
            "role": "user",
            "content": user_input,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # Prepare context for agent
        context = {
            "logs": st.session_state.get('log_data', []),
            "database_results": st.session_state.get('db_data'),
            "xml_context": st.session_state.get('xml_context'),
            "problem_statement": st.session_state.get('problem_statement')
        }
        
        # Create a placeholder for real-time thinking display
        thinking_placeholder = st.empty()
        progress_placeholder = st.empty()
        
        try:
            # Show initial thinking status
            with thinking_placeholder.container():
                st.info("🧠 **Agent Thinking Process:**")
                thinking_display = st.empty()
                thinking_display.write("💭 Processing your question and gathering context...")
            
            with progress_placeholder.container():
                progress_bar = st.progress(0)
                status_text = st.empty()
                status_text.text("Step 1/4: Analyzing question and context")
            
            # Get response from War Room agent with real-time updates
            agent_response = st.session_state.war_room_agent.chat_with_updates(
                user_input, context, thinking_display, progress_bar, status_text
            )
            
            # Clear the thinking placeholders
            thinking_placeholder.empty()
            progress_placeholder.empty()
            
            # Add agent response to history
            st.session_state.war_room_messages.append({
                "role": "assistant",
                "content": agent_response.get("response", "No response generated"),
                "thinking": agent_response.get("thinking_process", ""),
                "used_web_search": agent_response.get("used_web_search", False),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Set flag to clear input on next render
            st.session_state.message_sent = True
            
            st.success("✅ Response generated!")
            st.rerun()
            
        except Exception as e:
            thinking_placeholder.empty()
            progress_placeholder.empty()
            st.error(f"Error: {str(e)}")
            enterprise_logger.log_error(e, "War Room chat error")
    elif send_clicked:
        st.warning("Please enter a message first")
    
    with col2:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.war_room_messages = []
            st.session_state.message_sent = True  # This will clear input on next render
            if hasattr(st.session_state, 'war_room_agent'):
                st.session_state.war_room_agent.clear_conversation()
            st.success("Chat cleared!")
            st.rerun()
    
    with col3:
        if st.button("📤 Export Chat", use_container_width=True):
            if st.session_state.war_room_messages:
                chat_export = {
                    "export_timestamp": datetime.now().isoformat(),
                    "conversation": st.session_state.war_room_messages,
                    "context_summary": {
                        "logs_available": bool(st.session_state.get('log_data')),
                        "log_count": len(st.session_state.get('log_data') or []),
                        "database_results_available": bool(st.session_state.get('db_data')),
                        "xml_context_available": bool(st.session_state.get('xml_context'))
                    }
                }
                
                st.download_button(
                    label="⬇️ Download Chat History",
                    data=json.dumps(chat_export, indent=2),
                    file_name=f"war_room_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            else:
                st.info("No chat history to export")

def handle_image_ocr():
    """Handle Image OCR processing and analysis"""
    st.header("Image OCR Analysis")
    st.markdown("**Extract text from screenshots and images, especially useful for Japanese error messages**")
    
    # Check if API key is available for AI analysis
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.warning("🔐 OpenAI API key not found. OCR extraction will work, but AI analysis of results will be unavailable.")
        st.info("💡 Set OPENAI_API_KEY in your Replit secrets to enable AI analysis of extracted text.")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📷 Image Upload & OCR")
        
        # Language selection for OCR
        ocr_handler = ImageOCRHandler()
        supported_languages = ocr_handler.get_supported_languages()
        
        selected_languages = st.multiselect(
            "Select OCR Languages",
            options=list(supported_languages.keys()),
            default=['eng', 'jpn'],
            format_func=lambda x: f"{supported_languages[x]} ({x})",
            help="Select languages for text recognition. Japanese + English is recommended for Japanese error messages."
        )
        
        # Image upload
        uploaded_image = st.file_uploader(
            "Upload Screenshot or Image",
            type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'],
            help="Upload screenshots of error messages, application interfaces, or any image containing text"
        )
        
        if uploaded_image:
            # Validate image
            is_valid, message = ocr_handler.validate_image(uploaded_image)
            if not is_valid:
                st.error(f"❌ {message}")
                return
            
            # Display uploaded image
            st.image(uploaded_image, caption=f"Uploaded: {uploaded_image.name}", use_container_width=True)
            
            # Process OCR button
            if st.button("🔍 Extract Text with OCR", type="primary", use_container_width=True):
                with st.spinner("Extracting text from image..."):
                    try:
                        ocr_result = ocr_handler.extract_text_from_image(
                            uploaded_image, 
                            languages=selected_languages
                        )
                        
                        if 'error' in ocr_result:
                            st.error(f"❌ OCR failed: {ocr_result['error']}")
                        else:
                            st.session_state.ocr_results = ocr_result
                            st.success("✅ Text extraction completed!")
                            st.rerun()
                            
                    except Exception as e:
                        st.error(f"❌ OCR processing error: {str(e)}")
    
    with col2:
        st.subheader("🤖 AI Analysis")
        
        if st.session_state.ocr_results:
            # Display extracted text
            ocr_data = st.session_state.ocr_results
            
            st.write("**Extracted Text:**")
            if ocr_data['extracted_text']:
                st.text_area(
                    "OCR Results", 
                    value=ocr_data['extracted_text'], 
                    height=200, 
                    disabled=True
                )
                
                # Show confidence statistics
                col_a, col_b = st.columns(2)
                with col_a:
                    st.metric("Total Segments", ocr_data['total_segments'])
                with col_b:
                    st.metric("High Confidence", ocr_data['high_confidence_count'])
                
            else:
                st.warning("⚠️ No text was extracted from the image")
                return
            
            # User query input
            st.write("**What would you like to know about this image?**")
            user_query = st.text_area(
                "Your Question",
                placeholder="Examples:\n• What is the error message in this screenshot?\n• Translate the Japanese text to English\n• What steps should I take to resolve this issue?\n• Summarize the information shown in this image",
                height=120
            )
            
            # AI Analysis button
            if st.button("🚀 Analyze with AI", type="primary", use_container_width=True):
                if not user_query.strip():
                    st.warning("Please enter a question about the image")
                    return
                
                if not api_key:
                    st.error("OpenAI API key required for AI analysis")
                    return
                
                with st.spinner("Analyzing extracted text with AI..."):
                    try:
                        # Prepare context for AI analysis
                        analysis_context = ocr_handler.analyze_extracted_text(ocr_data, user_query)
                        
                        # Use AI analyzer with OCR context
                        ai_analyzer = AIAnalyzer()
                        ai_context = {
                            'image_ocr_data': analysis_context,
                            'user_query': user_query,
                            'problem_statement': f"Image Analysis: {user_query}"
                        }
                        
                        analysis_result = ai_analyzer.analyze_logs(ai_context)
                        st.session_state.ocr_analysis = analysis_result
                        
                        st.success("✅ AI analysis completed!")
                        st.rerun()
                        
                    except Exception as e:
                        st.error(f"❌ AI analysis error: {str(e)}")
        else:
            st.info("📋 Upload and process an image first to see AI analysis options")
    
    # Display analysis results
    if st.session_state.ocr_analysis:
        st.markdown("---")
        st.subheader("📊 Analysis Results")
        
        results = st.session_state.ocr_analysis
        
        if 'error' in results:
            st.error(f"Analysis failed: {results['error']}")
        else:
            # Create result tabs
            result_tabs = st.tabs(["📝 Summary", "🔤 Translation", "💡 Recommendations", "📋 Details"])
            
            with result_tabs[0]:  # Summary
                if 'summary' in results:
                    st.markdown("### Analysis Summary")
                    st.info(results['summary'])
                
                if 'key_findings' in results:
                    st.markdown("### Key Findings")
                    for finding in results['key_findings']:
                        st.write(f"• {finding}")
            
            with result_tabs[1]:  # Translation
                if 'translation' in results:
                    st.markdown("### Translation")
                    st.success(results['translation'])
                
                if 'original_text' in results:
                    st.markdown("### Original Text")
                    st.text_area("Original", value=results['original_text'], disabled=True, height=100)
            
            with result_tabs[2]:  # Recommendations
                if 'recommendations' in results:
                    st.markdown("### Recommendations")
                    for i, rec in enumerate(results['recommendations'], 1):
                        st.write(f"{i}. {rec}")
                
                if 'troubleshooting_steps' in results:
                    st.markdown("### Troubleshooting Steps")
                    for i, step in enumerate(results['troubleshooting_steps'], 1):
                        st.write(f"**Step {i}:** {step}")
            
            with result_tabs[3]:  # Details
                st.markdown("### OCR Processing Details")
                if st.session_state.ocr_results:
                    ocr_info = st.session_state.ocr_results['image_info']
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Image Size", f"{ocr_info['size'][0]}x{ocr_info['size'][1]}")
                    with col2:
                        st.metric("Format", ocr_info['format'])
                    with col3:
                        st.metric("Languages", ", ".join(st.session_state.ocr_results['languages_used']))
                
                # Export results
                if st.button("📤 Export Analysis Results"):
                    export_data = {
                        'timestamp': datetime.now().isoformat(),
                        'image_info': st.session_state.ocr_results.get('image_info', {}),
                        'extracted_text': st.session_state.ocr_results.get('extracted_text', ''),
                        'user_query': st.session_state.ocr_analysis.get('user_query', ''),
                        'analysis_results': results
                    }
                    
                    st.download_button(
                        label="⬇️ Download OCR Analysis",
                        data=json.dumps(export_data, indent=2, ensure_ascii=False),
                        file_name=f"ocr_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )

def handle_realtime_monitoring():
    """Handle real-time log monitoring and streaming analysis"""
    st.header("Real-time Log Monitor")
    st.markdown("**Monitor live log files for user activities, transactions, and errors**")
    
    # Check if API key is available
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.warning("🔐 OpenAI API key not found. Live monitoring will work, but AI analysis will be unavailable.")
        st.info("💡 Set OPENAI_API_KEY in your Replit secrets to enable AI analysis of live activities.")
    
    monitor = st.session_state.realtime_monitor
    
    # Main layout
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📡 Log File Configuration")
        
        # File path input
        log_path = st.text_input(
            "Log File Path",
            placeholder="Examples:\n• /var/log/application.log\n• \\\\server\\logs\\app.log\n• C:\\logs\\system.log",
            help="Enter the full path to the log file you want to monitor. Supports local paths, UNC paths, and NAS mounts."
        )
        
        # Monitoring options
        col_a, col_b = st.columns(2)
        with col_a:
            start_from_end = st.checkbox(
                "Start from EOF", 
                value=True,
                help="Start monitoring from the end of file (recommended for live monitoring)"
            )
        with col_b:
            auto_analyze = st.checkbox(
                "Auto AI Analysis",
                value=False,
                help="Automatically analyze activities every 10 new log lines"
            )
        
        # Control buttons
        button_col1, button_col2 = st.columns(2)
        
        with button_col1:
            if st.button("🚀 Start Monitoring", type="primary", use_container_width=True, disabled=not log_path):
                if log_path:
                    with st.spinner("Starting log monitoring..."):
                        success = monitor.start_monitoring(log_path, start_from_end)
                        if success:
                            st.session_state.monitoring_active = True
                            st.success("✅ Monitoring started!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to start monitoring. Check the logs for details.")
        
        with button_col2:
            if st.button("⏹️ Stop Monitoring", use_container_width=True):
                monitor.stop_monitoring()
                st.session_state.monitoring_active = False
                st.info("🛑 Monitoring stopped")
                st.rerun()
        
        # Current status
        if st.session_state.monitoring_active:
            stats = monitor.get_monitoring_stats()
            st.success("🟢 **Monitoring Active**")
            st.metric("Queue Size", stats['queue_size'])
            if stats['file_path']:
                st.code(f"Monitoring: {stats['file_path']}")
        else:
            st.info("🔴 **Monitoring Inactive**")
    
    with col2:
        st.subheader("🤖 AI Analysis Control")
        
        # Analysis context
        analysis_context = st.text_area(
            "Analysis Context",
            placeholder="Describe what you're monitoring for:\n• User login patterns\n• Transaction failures\n• Performance issues\n• Security incidents",
            height=100
        )
        
        # Batch analysis controls
        if st.session_state.live_activities:
            activity_count = len(st.session_state.live_activities)
            st.metric("Live Activities", activity_count)
            
            if api_key and st.button("🧠 Analyze Current Batch", type="secondary", use_container_width=True):
                if activity_count > 0:
                    with st.spinner("Analyzing live activities..."):
                        try:
                            analysis = monitor.analyze_activity_batch(
                                st.session_state.live_activities,
                                analysis_context
                            )
                            st.session_state.batch_analysis = analysis
                            st.success(f"✅ Analyzed {activity_count} activities")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Analysis failed: {str(e)}")
            
            # Clear activities button
            if st.button("🗑️ Clear Activities", use_container_width=True):
                st.session_state.live_activities = []
                st.rerun()
        else:
            st.info("📋 No live activities captured yet")
    
    # Live activity feed
    st.markdown("---")
    st.subheader("📊 Live Activity Feed")
    
    # Auto-refresh mechanism
    if st.session_state.monitoring_active:
        # Get new log updates
        updates = monitor.get_log_updates()
        
        # Process updates
        new_activities = 0
        for update in updates:
            if update['type'] == 'log_line':
                activity = update['data']
                if activity['activities']:  # Only show lines with detected activities
                    st.session_state.live_activities.append(activity)
                    new_activities += 1
            elif update['type'] == 'error':
                st.error(f"Monitor Error: {update['data']['error']}")
            elif update['type'] == 'monitoring_started':
                st.success(f"✅ {update['data']['message']}")
            elif update['type'] == 'monitoring_stopped':
                st.info(f"🛑 {update['data']['message']}")
                st.session_state.monitoring_active = False
            elif update['type'] == 'file_rotated':
                st.warning(f"🔄 {update['data']['message']}")
        
        # Auto-refresh the page to show new activities
        if updates:
            st.rerun()
        
        # Show refresh hint if monitoring but no new data
        if not updates:
            st.empty().markdown("*Monitoring for new log entries... (auto-refresh)*")
            time.sleep(2)
            st.rerun()
    
    # Display recent activities
    if st.session_state.live_activities:
        # Activity summary metrics
        activities = st.session_state.live_activities[-20:]  # Show last 20
        
        col_metrics = st.columns(4)
        login_count = sum(1 for a in activities if any(act['type'] == 'login' for act in a['activities']))
        transaction_count = sum(1 for a in activities if any(act['type'] == 'transaction' for act in a['activities']))
        error_count = sum(1 for a in activities if any(act['type'] == 'error' for act in a['activities']))
        high_priority = sum(1 for a in activities if a['priority'] == 'HIGH')
        
        with col_metrics[0]:
            st.metric("Logins", login_count)
        with col_metrics[1]:
            st.metric("Transactions", transaction_count)
        with col_metrics[2]:
            st.metric("Errors", error_count)
        with col_metrics[3]:
            st.metric("High Priority", high_priority)
        
        # Activity timeline
        st.markdown("### Recent Activities")
        for activity in reversed(activities):  # Show newest first
            priority_color = {
                'HIGH': '🔴',
                'MEDIUM': '🟡', 
                'LOW': '🟢'
            }.get(activity['priority'], '⚪')
            
            with st.expander(f"{priority_color} {activity['log_timestamp'] if 'log_timestamp' in activity else activity['timestamp'][:19]} - {len(activity['activities'])} activities"):
                # Show original log line
                st.code(activity['original_line'])
                
                # Show detected activities
                for act in activity['activities']:
                    st.write(f"**{act['type'].title()}**: {act['matches']}")
    
    # Show AI analysis results
    if hasattr(st.session_state, 'batch_analysis') and st.session_state.batch_analysis:
        st.markdown("---")
        st.subheader("🧠 AI Analysis Results")
        
        analysis = st.session_state.batch_analysis
        
        if 'error' in analysis:
            st.error(f"Analysis Error: {analysis['error']}")
        else:
            # Create analysis tabs
            analysis_tabs = st.tabs(["📝 Summary", "🔍 Insights", "⚠️ Alerts", "📊 Patterns"])
            
            with analysis_tabs[0]:  # Summary
                if 'summary' in analysis:
                    st.info(analysis['summary'])
                if 'key_findings' in analysis:
                    st.markdown("**Key Findings:**")
                    for finding in analysis['key_findings']:
                        st.write(f"• {finding}")
            
            with analysis_tabs[1]:  # Insights
                if 'insights' in analysis:
                    for insight in analysis['insights']:
                        st.success(f"💡 {insight}")
                if 'recommendations' in analysis:
                    st.markdown("**Recommendations:**")
                    for rec in analysis['recommendations']:
                        st.write(f"→ {rec}")
            
            with analysis_tabs[2]:  # Alerts
                if 'security_alerts' in analysis:
                    for alert in analysis['security_alerts']:
                        st.error(f"🚨 {alert}")
                if 'performance_alerts' in analysis:
                    for alert in analysis['performance_alerts']:
                        st.warning(f"⚡ {alert}")
            
            with analysis_tabs[3]:  # Patterns
                if 'patterns' in analysis:
                    for pattern in analysis['patterns']:
                        st.write(f"📈 {pattern}")
                if 'trends' in analysis:
                    for trend in analysis['trends']:
                        st.write(f"📊 {trend}")
            
            # Export analysis
            if st.button("📤 Export Live Analysis"):
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'activities_analyzed': len(st.session_state.live_activities),
                    'analysis_context': analysis_context,
                    'analysis_results': analysis,
                    'recent_activities': st.session_state.live_activities[-10:]  # Last 10 activities
                }
                
                st.download_button(
                    label="⬇️ Download Live Analysis",
                    data=json.dumps(export_data, indent=2, ensure_ascii=False),
                    file_name=f"live_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

if __name__ == "__main__":
    main()
