import pandas as pd
import pyodbc
import urllib.parse
from typing import Optional
import streamlit as st

class DatabaseHandler:
    """Handles SQL Server database connections and queries"""
    
    def __init__(self):
        self.connection = None
    
    def execute_query(self, server: str, database: str, username: str, 
                     password: str, query: str) -> Optional[pd.DataFrame]:
        """
        Execute SQL query and return results as pandas DataFrame
        
        Args:
            server: SQL Server hostname
            database: Database name
            username: Username for authentication
            password: Password for authentication
            query: SQL query to execute
            
        Returns:
            DataFrame with query results or None if no results
        """
        try:
            # Build connection string
            connection_string = self._build_connection_string(
                server, database, username, password
            )
            
            # Execute query
            with pyodbc.connect(connection_string, timeout=30) as conn:
                df = pd.read_sql(query, conn)
                return df
                
        except pyodbc.Error as e:
            raise Exception(f"Database connection error: {str(e)}")
        except pd.errors.DatabaseError as e:
            raise Exception(f"Query execution error: {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected database error: {str(e)}")
    
    def _build_connection_string(self, server: str, database: str, 
                               username: str, password: str) -> str:
        """
        Build SQL Server connection string
        
        Args:
            server: SQL Server hostname
            database: Database name  
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Connection string for pyodbc
        """
        # URL encode password to handle special characters
        encoded_password = urllib.parse.quote_plus(password)
        
        connection_string = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={username};"
            f"PWD={encoded_password};"
            f"TrustServerCertificate=yes;"
            f"Connection Timeout=30;"
        )
        
        return connection_string
    
    def test_connection(self, server: str, database: str, 
                       username: str, password: str) -> bool:
        """
        Test database connection
        
        Args:
            server: SQL Server hostname
            database: Database name
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Boolean indicating if connection was successful
        """
        try:
            connection_string = self._build_connection_string(
                server, database, username, password
            )
            
            with pyodbc.connect(connection_string, timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                return True
                
        except Exception:
            return False
    
    def get_table_list(self, server: str, database: str, 
                      username: str, password: str) -> Optional[pd.DataFrame]:
        """
        Get list of tables in the database
        
        Args:
            server: SQL Server hostname
            database: Database name
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            DataFrame containing table information
        """
        query = """
        SELECT 
            TABLE_SCHEMA,
            TABLE_NAME,
            TABLE_TYPE
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_SCHEMA, TABLE_NAME
        """
        
        return self.execute_query(server, database, username, password, query)
