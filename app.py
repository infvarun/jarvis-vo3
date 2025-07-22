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
    
    # Analysis options
    col1, col2 = st.columns(2)
    
    with col1:
        start_time = st.text_input(
            "Start Time Filter (optional)",
            placeholder="YYYY-MM-DD HH:MM:SS"
        )
        
    with col2:
        end_time = st.text_input(
            "End Time Filter (optional)",
            placeholder="YYYY-MM-DD HH:MM:SS"
        )
    
    log_level_filter = st.multiselect(
        "Filter by Log Level",
        options=['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'],
        default=['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL']
    )
    
    if st.button("🤖 Start AI Analysis", type="primary"):
        try:
            with st.spinner("Analyzing logs with AI..."):
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

def display_results():
    st.header("Analysis Results")
    
    if not st.session_state.analysis_results:
        st.info("No analysis results available. Please run the analysis first.")
        return
    
    results = st.session_state.analysis_results
    
    # Summary section
    st.subheader("📋 Executive Summary")
    st.write(results.get('summary', 'No summary available'))
    
    # Error categorization
    if 'error_categories' in results:
        st.subheader("🚨 Error Categories")
        for category in results['error_categories']:
            with st.expander(f"{category.get('category', 'Unknown')} ({category.get('count', 0)} occurrences)"):
                st.write(f"**Severity**: {category.get('severity', 'Unknown')}")
                st.write(f"**Description**: {category.get('description', 'No description')}")
                if category.get('examples'):
                    st.write("**Examples**:")
                    for example in category['examples'][:3]:  # Show first 3 examples
                        st.code(example, language='text')
    
    # Recommendations
    if 'recommendations' in results:
        st.subheader("💡 Recommendations")
        for i, rec in enumerate(results['recommendations'], 1):
            st.write(f"**{i}.** {rec}")
    
    # Affected services
    if 'affected_services' in results:
        st.subheader("🏗️ Affected Services/Components")
        services_df = pd.DataFrame(results['affected_services'])
        st.dataframe(services_df, use_container_width=True)
    
    # Timeline analysis
    if 'timeline' in results:
        st.subheader("⏰ Timeline Analysis")
        st.write(results['timeline'])
    
    # Database context (if available)
    if st.session_state.db_data is not None:
        st.subheader("🗄️ Database Context")
        st.write("Database query results were included in the analysis:")
        st.dataframe(st.session_state.db_data, use_container_width=True)
    
    # XML context (if available)
    if st.session_state.xml_context:
        st.subheader("📄 XML Context")
        for xml_file in st.session_state.xml_context:
            with st.expander(f"XML File: {xml_file['filename']}"):
                st.text(xml_file['content'][:1000] + "..." if len(xml_file['content']) > 1000 else xml_file['content'])
    
    # Export functionality
    st.subheader("📤 Export Results")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Export as Text"):
            export_text = generate_text_report(results)
            st.download_button(
                label="Download Report",
                data=export_text,
                file_name=f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    with col2:
        if st.button("📊 Export as JSON"):
            import json
            export_json = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="Download JSON",
                data=export_json,
                file_name=f"log_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

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
