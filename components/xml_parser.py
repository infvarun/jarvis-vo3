import xml.etree.ElementTree as ET
import streamlit as st
from typing import Dict, Any

class XMLParser:
    """Handles XML file parsing and content extraction"""
    
    def __init__(self):
        pass
    
    def parse_xml_file(self, uploaded_file) -> str:
        """
        Parse uploaded XML file and extract content
        
        Args:
            uploaded_file: Streamlit uploaded file object
            
        Returns:
            String representation of parsed XML content
        """
        try:
            # Read file content
            content = uploaded_file.read()
            
            # Try to decode as UTF-8, fallback to latin-1 if needed
            try:
                xml_content = content.decode('utf-8')
            except UnicodeDecodeError:
                xml_content = content.decode('latin-1')
            
            # Parse XML
            root = ET.fromstring(xml_content)
            
            # Convert to readable format
            parsed_content = self._xml_to_text(root)
            
            return parsed_content
            
        except ET.ParseError as e:
            raise Exception(f"XML parsing error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to process XML file: {str(e)}")
    
    def _xml_to_text(self, element, level=0) -> str:
        """
        Convert XML element tree to readable text format
        
        Args:
            element: XML element
            level: Indentation level
            
        Returns:
            String representation of XML content
        """
        result = []
        indent = "  " * level
        
        # Element name and attributes
        tag_info = f"{indent}<{element.tag}"
        if element.attrib:
            attrs = " ".join([f'{k}="{v}"' for k, v in element.attrib.items()])
            tag_info += f" {attrs}"
        tag_info += ">"
        result.append(tag_info)
        
        # Element text content
        if element.text and element.text.strip():
            result.append(f"{indent}  {element.text.strip()}")
        
        # Child elements
        for child in element:
            result.append(self._xml_to_text(child, level + 1))
        
        # Closing tag
        result.append(f"{indent}</{element.tag}>")
        
        return "\n".join(result)
    
    def extract_xml_metadata(self, uploaded_file) -> Dict[str, Any]:
        """
        Extract metadata from XML file
        
        Args:
            uploaded_file: Streamlit uploaded file object
            
        Returns:
            Dictionary containing XML metadata
        """
        try:
            content = uploaded_file.read()
            xml_content = content.decode('utf-8')
            root = ET.fromstring(xml_content)
            
            metadata = {
                'root_tag': root.tag,
                'attributes': root.attrib,
                'child_count': len(root),
                'namespace': self._extract_namespace(root.tag)
            }
            
            return metadata
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_namespace(self, tag: str) -> str:
        """
        Extract namespace from XML tag
        
        Args:
            tag: XML tag name
            
        Returns:
            Namespace string or empty string if no namespace
        """
        if '}' in tag:
            return tag.split('}')[0][1:]  # Remove leading '{'
        return ""
    
    def search_xml_content(self, xml_content: str, search_terms: list) -> Dict[str, list]:
        """
        Search for specific terms in XML content
        
        Args:
            xml_content: String representation of XML content
            search_terms: List of terms to search for
            
        Returns:
            Dictionary mapping search terms to found locations
        """
        results = {}
        lines = xml_content.split('\n')
        
        for term in search_terms:
            matches = []
            for i, line in enumerate(lines, 1):
                if term.lower() in line.lower():
                    matches.append({
                        'line_number': i,
                        'content': line.strip()
                    })
            results[term] = matches
        
        return results
