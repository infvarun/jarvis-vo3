# Log Analysis Tool - replit.md

## Overview

This is a Streamlit-based log analysis tool that provides intelligent troubleshooting insights using AI-powered analysis. The application allows users to upload log files, query databases, parse XML context, and perform AI-driven analysis to identify patterns and issues in system logs.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

**July 25, 2025**
- Implemented "War Room" agentic chat feature using LangGraph:
  - Intelligent agent that can analyze logs, query databases, and search for solutions
  - LangGraph-based workflow with thinking/reflection capabilities for refined responses
  - Web search integration (StackOverflow) for technical solutions and documentation
  - Context-aware chat that understands available log files, database results, and XML data
  - Visual thinking process display showing agent's reasoning steps
  - Quick suggestion buttons for common troubleshooting scenarios
  - Chat history with export functionality and conversation memory
- Implemented comprehensive enterprise-grade features for production deployment:
  - Advanced security layer with file validation, SQL injection protection, and session management
  - Performance monitoring with real-time system metrics and operation tracking
  - Intelligent caching system for file processing and AI analysis results
  - Enterprise logging with audit trails and security event tracking
  - Configuration management with environment-based settings
  - Enterprise dashboard sidebar with system metrics, performance stats, and cache statistics
- Enhanced user interface with professional icons and clean gradient design
- Added user-friendly date/time pickers instead of manual text input
- Optimized AI analysis with caching to reduce API calls and improve response times
- Implemented comprehensive error handling and security validation throughout

**July 23, 2025**
- Updated AI analyzer to use LangChain instead of direct OpenAI client integration
- Enhanced Analysis tab with improved result formatting and organization
- Configured proper environment variable approach for OpenAI API key
- Created sample JBoss clinical IRT system log with realistic order failures for testing

## System Architecture

The application follows a modular, component-based architecture built on top of Streamlit for the web interface. The system is designed around four main workflows:

1. **File Processing Pipeline**: Handles log file uploads and parsing
2. **Database Integration**: Enables SQL Server queries for additional context
3. **AI Analysis Engine**: Processes logs using OpenAI's GPT-4o model
4. **Results Presentation**: Displays analysis results through an interactive web interface

### Frontend Architecture

- **Framework**: Streamlit with a multi-tab interface
- **Layout**: Wide layout with four main tabs (File Upload, Database Query, Analysis, Results)
- **State Management**: Uses Streamlit's session state for maintaining data across interactions
- **UI Components**: Organized into columns for better user experience

### Backend Architecture

- **Modular Design**: Component-based architecture with separate handlers for different functionalities
- **Service Layer**: Individual classes handle specific responsibilities (file handling, database operations, XML parsing, etc.)
- **Utility Layer**: Shared utilities like log parsing logic

## Key Components

### 1. File Handler (`components/file_handler.py`)
- **Purpose**: Manages file upload and processing operations
- **Functionality**: Processes log files with UTF-8/latin-1 encoding fallback
- **Integration**: Uses LogParser utility for structured data extraction
- **Validation**: Includes file size validation (50MB default limit)

### 2. Database Handler (`components/database_handler.py`)
- **Purpose**: Handles SQL Server database connections and queries
- **Technology**: Uses pyodbc for database connectivity
- **Security**: Builds secure connection strings with proper parameter handling
- **Error Handling**: Comprehensive exception handling for database operations

### 3. XML Parser (`components/xml_parser.py`)
- **Purpose**: Parses XML files for additional context
- **Technology**: Uses Python's built-in xml.etree.ElementTree
- **Output**: Converts XML structure to readable text format
- **Error Handling**: Handles XML parsing errors gracefully

### 4. Log Analyzer (`components/log_analyzer.py`)
- **Purpose**: Performs log filtering and basic analysis operations
- **Filtering**: Time-based and log level filtering capabilities
- **Log Levels**: Supports standard log levels (DEBUG, INFO, WARN, ERROR, etc.)

### 5. AI Analyzer (`components/ai_analyzer.py`)
- **Purpose**: AI-powered log analysis using OpenAI
- **Model**: Uses GPT-4o (latest OpenAI model as of May 2024)
- **Output**: Structured JSON responses for consistent analysis results
- **Context**: Integrates log data with database and XML context

### 6. Log Parser (`utils/log_parser.py`)
- **Purpose**: Utility for parsing various log formats
- **Patterns**: Supports multiple timestamp and log level patterns
- **Flexibility**: Handles different log formats and structures
- **Component Detection**: Extracts service/component information from logs

## Data Flow

1. **Input Stage**: Users upload log files, XML context files, or input database queries
2. **Processing Stage**: 
   - Log files are parsed into structured data
   - Database queries are executed
   - XML files are parsed for context
3. **Analysis Stage**: AI analyzer combines all available data for comprehensive analysis
4. **Output Stage**: Results are presented through the Streamlit interface with structured insights

## External Dependencies

### Core Dependencies
- **Streamlit**: Web interface framework
- **Pandas**: Data manipulation and analysis
- **OpenAI**: AI analysis capabilities using GPT-4o model
- **pyodbc**: SQL Server database connectivity

### System Dependencies
- **Python Standard Library**: xml.etree.ElementTree, re, datetime, os
- **File Handling**: Built-in file I/O operations

### API Keys
- **OpenAI API Key**: Required for AI analysis functionality
- **Environment Variable**: `OPENAI_API_KEY`

## Deployment Strategy

### Development Environment
- **Runtime**: Python-based Streamlit application
- **Configuration**: Page config set for wide layout with custom title and icon
- **Session Management**: Uses Streamlit's built-in session state

### Production Considerations
- **Environment Variables**: OpenAI API key must be configured
- **Database Access**: SQL Server connectivity requires network access and credentials
- **File Upload Limits**: Default 50MB file size limit (configurable)
- **Error Handling**: Comprehensive exception handling throughout all components

### Scalability Features
- **Modular Design**: Components can be easily extended or modified
- **Stateless Operations**: Most operations are stateless except for session data
- **Memory Management**: File processing includes encoding fallbacks for various file types

## Enterprise Features

### Security & Compliance
- **File Upload Security**: Comprehensive validation including file size limits, extension checking, and content scanning for malicious patterns
- **SQL Injection Protection**: Query sanitization and validation to prevent dangerous SQL operations
- **Session Management**: Secure token-based session handling with automatic renewal and validation
- **Audit Logging**: Complete audit trail of user actions, security events, and system operations

### Performance & Scalability
- **Intelligent Caching**: Multi-level caching for file processing and AI analysis results to reduce processing time and API costs
- **Performance Monitoring**: Real-time tracking of system metrics (CPU, memory) and operation performance with threshold alerts
- **Resource Management**: Configurable limits for file sizes, database queries, and concurrent operations
- **Response Time Optimization**: Cached results and optimized processing pipelines for sub-second response times

### Monitoring & Observability
- **Enterprise Dashboard**: Real-time system metrics, performance statistics, and cache analytics in sidebar
- **Comprehensive Logging**: Structured logging with different levels (DEBUG, INFO, WARNING, ERROR) and log rotation
- **Performance Metrics**: Detailed tracking of operation success rates, average response times, and system resource usage
- **Configuration Validation**: Real-time validation of required environment variables and system settings

### Data Management
- **Smart Caching Strategy**: Hash-based caching with TTL management and automatic cleanup of expired entries
- **Memory Optimization**: Efficient data structures and garbage collection for large log file processing
- **Database Connection Pooling**: Optimized database connections with timeout management and error recovery
- **File Processing Pipeline**: Streamlined processing with encoding fallbacks and error recovery mechanisms

The architecture now provides enterprise-grade reliability, security, and performance suitable for production deployment in corporate environments while maintaining the intuitive user experience for log analysis and troubleshooting.