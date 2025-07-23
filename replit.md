# Log Analysis Tool - replit.md

## Overview

This is a Streamlit-based log analysis tool that provides intelligent troubleshooting insights using AI-powered analysis. The application allows users to upload log files, query databases, parse XML context, and perform AI-driven analysis to identify patterns and issues in system logs.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

**July 23, 2025**
- Updated AI analyzer to use LangChain instead of direct OpenAI client integration
- Enhanced Analysis tab with improved result formatting and organization:
  - Split layout with options on left and results on right
  - Tabbed result display (Summary, Errors, Recommendations, Details, Export)
  - Color-coded severity indicators for error categories
  - Key metrics dashboard with total errors and affected services
  - Enhanced export functionality with professional download options
  - Better organization with expandable sections and cleaner UI

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

The architecture prioritizes modularity, error resilience, and user experience while providing powerful AI-driven insights for log analysis and troubleshooting.