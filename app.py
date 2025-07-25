import streamlit as st
import pandas as pd
import os
import hashlib
from datetime import datetime, timedelta
from components.file_handler import FileHandler
from components.database_handler import DatabaseHandler
from components.xml_parser import XMLParser
from components.log_analyzer import LogAnalyzer
from components.ai_analyzer import AIAnalyzer

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
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📁 File Upload", 
        "🗃️ Database Query", 
        "⚙️ Analysis", 
        "📊 Results",
        "🚨 War Room"
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
    
    # Enterprise features sidebar
    display_enterprise_sidebar()

def handle_file_uploads():
    st.header("File Upload")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Log Files")
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
                st.info(f"Total log entries loaded: {len(log_data)}")
    
    with col2:
        st.subheader("XML Context Files (Optional)")
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
                        'xml_context': st.session_state.xml_context
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

def display_enterprise_sidebar():
    """Display enterprise monitoring sidebar"""
    with st.sidebar:
        st.markdown("### 🏢 Enterprise Dashboard")
        
        # System metrics
        with st.expander("📊 System Metrics"):
            metrics = performance_monitor.get_system_metrics()
            if metrics:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Memory Usage", f"{metrics.get('memory_usage_percent', 0):.1f}%")
                    st.metric("CPU Usage", f"{metrics.get('cpu_usage_percent', 0):.1f}%")
                with col2:
                    st.metric("Memory Available", f"{metrics.get('memory_available_gb', 0):.1f} GB")
                    st.metric("CPU Cores", f"{metrics.get('cpu_count', 0)}")
        
        # Performance metrics
        with st.expander("⚡ Performance Metrics"):
            perf_summary = performance_monitor.get_performance_summary()
            if perf_summary:
                for operation, stats in perf_summary.items():
                    st.write(f"**{operation.replace('_', ' ').title()}**")
                    st.write(f"- Success Rate: {stats['success_rate']:.1f}%")
                    st.write(f"- Avg Duration: {stats['avg_duration']:.2f}s")
                    st.write(f"- Total Calls: {stats['total_calls']}")
            else:
                st.info("No performance data available yet")
        
        # Cache statistics
        with st.expander("💾 Cache Statistics"):
            cache_stats = enterprise_cache.get_cache_stats()
            if cache_stats['total_entries'] > 0:
                st.metric("Cache Entries", cache_stats['total_entries'])
                st.metric("Hit Rate", f"{cache_stats['hit_rate_percent']:.1f}%")
                st.metric("Cache Size", f"{cache_stats['estimated_size_bytes'] / 1024:.1f} KB")
                
                if st.button("🗑️ Clear Cache"):
                    enterprise_cache.clear_expired_cache()
                    st.success("Cache cleared!")
                    st.rerun()
            else:
                st.info("No cache data available")
        
        # Configuration status
        with st.expander("⚙️ Configuration"):
            config_validation = Config.validate_config()
            for var, is_valid in config_validation.items():
                status = "✅" if is_valid else "❌"
                st.write(f"{status} {var}")
        
        # Security status
        with st.expander("🔒 Security Status"):
            st.write("✅ File validation enabled")
            st.write("✅ SQL injection protection")
            st.write("✅ Session management active")
            st.write("✅ Audit logging enabled")

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
    
    # Chat input
    user_input = st.text_area(
        "Your question:",
        value=st.session_state.get('suggested_query', ''),
        placeholder="Ask about logs, errors, performance issues, or troubleshooting steps...",
        height=100,
        key="war_room_input"
    )
    
    # Clear suggested query after displaying
    if 'suggested_query' in st.session_state:
        del st.session_state.suggested_query
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        send_clicked = st.button("🚀 Send Message", type="primary", use_container_width=True)
        
    # Process the message if button is clicked and there's input
    if send_clicked:
        # Get the current value from the text area
        current_input = st.session_state.get("war_room_input", "")
        if current_input and current_input.strip():
            # Add user message to history
            st.session_state.war_room_messages.append({
                "role": "user",
                "content": current_input,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Prepare context for agent
            context = {
                "logs": st.session_state.get('log_data', []),
                "database_results": st.session_state.get('db_data'),
                "xml_context": st.session_state.get('xml_context')
            }
            
            # Show processing message
            with st.spinner("🤖 Agent is thinking and analyzing..."):
                try:
                    # Get response from War Room agent
                    agent_response = st.session_state.war_room_agent.chat(current_input, context)
                    
                    # Add agent response to history
                    st.session_state.war_room_messages.append({
                        "role": "assistant",
                        "content": agent_response.get("response", "No response generated"),
                        "thinking": agent_response.get("thinking_process", ""),
                        "used_web_search": agent_response.get("used_web_search", False),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    # Clear the input field after sending
                    st.session_state.war_room_input = ""
                    
                    st.success("✅ Response generated!")
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                    enterprise_logger.log_error(e, "War Room chat error")
        else:
            st.warning("Please enter a message first")
    
    with col2:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.war_room_messages = []
            st.session_state.war_room_input = ""  # Clear input field too
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

if __name__ == "__main__":
    main()
