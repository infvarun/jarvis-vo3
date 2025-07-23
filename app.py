import streamlit as st
import pandas as pd
import os
from datetime import datetime
from components.file_handler import FileHandler
from components.database_handler import DatabaseHandler
from components.xml_parser import XMLParser
from components.log_analyzer import LogAnalyzer
from components.ai_analyzer import AIAnalyzer

# Configure page
st.set_page_config(
    page_title="Log Analysis Tool",
    page_icon="🔍",
    layout="wide"
)

def main():
    st.title("🔍 Log Analysis Tool")
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

    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["📁 File Upload", "🗄️ Database Query", "🔍 Analysis", "📊 Results"])
    
    with tab1:
        handle_file_uploads()
    
    with tab2:
        handle_database_query()
    
    with tab3:
        handle_analysis()
    
    with tab4:
        display_results()

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
        start_time = st.text_input(
            "Start Time",
            placeholder="YYYY-MM-DD HH:MM:SS",
            key="start_time_filter"
        )
        end_time = st.text_input(
            "End Time", 
            placeholder="YYYY-MM-DD HH:MM:SS",
            key="end_time_filter"
        )
        
        # Log level filter
        st.write("**Log Level Filter**")
        log_level_filter = st.multiselect(
            "Select levels to analyze",
            options=['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'],
            default=['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL'],
            key="log_level_filter"
        )
        
        # Analysis button
        if st.button("🤖 Start AI Analysis", type="primary", use_container_width=True):
            try:
                with st.spinner("Analyzing logs with AI..."):
                    # Check if API key is available first
                    api_key = os.getenv("OPENAI_API_KEY")
                    if not api_key:
                        st.error("❌ OpenAI API key not found. Please set the OPENAI_API_KEY environment variable in your Replit secrets.")
                        st.info("Go to the Secrets tab in Replit and add OPENAI_API_KEY with your OpenAI API key.")
                        return
                    
                    log_analyzer = LogAnalyzer()
                    ai_analyzer = AIAnalyzer()
                    
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
                    
                    # Perform AI analysis
                    analysis_results = ai_analyzer.analyze_logs(context)
                    st.session_state.analysis_results = analysis_results
                    
                    st.success("✅ Analysis completed!")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"❌ Analysis error: {str(e)}")
        
        # Show data summary
        if st.session_state.log_data:
            st.write("**Data Summary**")
            st.info(f"📊 Total log entries: {len(st.session_state.log_data)}")
            
            if st.session_state.db_data is not None:
                st.info(f"🗄️ Database rows: {len(st.session_state.db_data)}")
            
            if st.session_state.xml_context:
                st.info(f"📄 XML files: {len(st.session_state.xml_context)}")
    
    with col2:
        st.subheader("Analysis Results")
        
        if st.session_state.analysis_results:
            display_analysis_results()
        else:
            st.info("🔍 Results will appear here after running analysis")

def display_analysis_results():
    """Display analysis results in a formatted way"""
    results = st.session_state.analysis_results
    
    if 'error' in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    # Create tabs for different result sections
    result_tabs = st.tabs(["📋 Summary", "🚨 Errors", "💡 Recommendations", "📊 Details", "📤 Export"])
    
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

if __name__ == "__main__":
    main()
