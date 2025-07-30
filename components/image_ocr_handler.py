"""
Image OCR Handler for extracting text from uploaded images
Particularly useful for Japanese error messages and screenshots
"""
import io
import base64
from typing import Dict, Any, List, Optional
from PIL import Image
import cv2
import numpy as np
import pytesseract
import streamlit as st

from utils.logger import enterprise_logger
from utils.performance import performance_monitor

class ImageOCRHandler:
    """Handles image upload and OCR text extraction"""
    
    def __init__(self):
        # Configure tesseract for better multi-language support
        self.tesseract_config = r'--oem 3 --psm 6'
        
    def validate_image(self, uploaded_file) -> tuple[bool, str]:
        """
        Validate uploaded image file
        
        Args:
            uploaded_file: Streamlit uploaded file object
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Check file size (max 10MB)
        max_size_mb = 10
        if uploaded_file.size > max_size_mb * 1024 * 1024:
            return False, f"File size exceeds {max_size_mb}MB limit"
        
        # Check file type
        allowed_types = ['image/png', 'image/jpeg', 'image/jpg', 'image/bmp', 'image/tiff']
        if uploaded_file.type not in allowed_types:
            return False, f"Unsupported file type. Allowed: PNG, JPEG, BMP, TIFF"
        
        return True, "Valid image file"
    
    def preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Preprocess image to improve OCR accuracy
        
        Args:
            image: PIL Image object
            
        Returns:
            Preprocessed PIL Image
        """
        try:
            # Convert PIL to OpenCV format
            opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # Convert to grayscale
            gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply denoising
            denoised = cv2.fastNlMeansDenoising(gray)
            
            # Apply adaptive thresholding for better text extraction
            thresh = cv2.adaptiveThreshold(
                denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            
            # Convert back to PIL
            preprocessed = Image.fromarray(thresh)
            
            return preprocessed
            
        except Exception as e:
            enterprise_logger.log_error(e, "Image preprocessing failed")
            # Return original image if preprocessing fails
            return image
    
    def extract_text_from_image(self, uploaded_file, languages: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Extract text from uploaded image using OCR
        
        Args:
            uploaded_file: Streamlit uploaded file object
            languages: List of language codes for OCR (e.g., ['eng', 'jpn'])
            
        Returns:
            Dictionary containing extracted text and metadata
        """
        try:
            # Default languages: English and Japanese
            if languages is None:
                languages = ['eng', 'jpn']
            
            # Load image
            image = Image.open(uploaded_file)
            
            # Get image info
            image_info = {
                'filename': uploaded_file.name,
                'format': image.format,
                'size': image.size,
                'mode': image.mode
            }
            
            # Preprocess image for better OCR
            processed_image = self.preprocess_image(image)
            
            # Extract text with multiple language support
            lang_string = '+'.join(languages)
            
            # Extract text with confidence scores
            extracted_data = pytesseract.image_to_data(
                processed_image, 
                lang=lang_string,
                config=self.tesseract_config,
                output_type=pytesseract.Output.DICT
            )
            
            # Extract plain text
            extracted_text = pytesseract.image_to_string(
                processed_image,
                lang=lang_string,
                config=self.tesseract_config
            )
            
            # Filter high-confidence text
            high_confidence_text = []
            for i, confidence in enumerate(extracted_data['conf']):
                if int(confidence) > 30:  # Only include text with >30% confidence
                    text = extracted_data['text'][i].strip()
                    if text:
                        high_confidence_text.append({
                            'text': text,
                            'confidence': confidence,
                            'bbox': {
                                'x': extracted_data['left'][i],
                                'y': extracted_data['top'][i],
                                'width': extracted_data['width'][i],
                                'height': extracted_data['height'][i]
                            }
                        })
            
            # Convert image to base64 for display
            buffered = io.BytesIO()
            image.save(buffered, format=image.format or "PNG")
            image_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            result = {
                'extracted_text': extracted_text.strip(),
                'high_confidence_segments': high_confidence_text,
                'image_info': image_info,
                'image_base64': image_base64,
                'languages_used': languages,
                'total_segments': len([t for t in extracted_data['text'] if t.strip()]),
                'high_confidence_count': len(high_confidence_text)
            }
            
            enterprise_logger.log_user_action(
                "IMAGE_OCR_PROCESSED",
                filename=uploaded_file.name,
                languages=lang_string,
                text_length=len(extracted_text),
                confidence_segments=len(high_confidence_text)
            )
            
            return result
            
        except Exception as e:
            enterprise_logger.log_error(e, f"OCR extraction failed for {uploaded_file.name}")
            return {
                'error': f"OCR extraction failed: {str(e)}",
                'extracted_text': '',
                'image_info': {'filename': uploaded_file.name}
            }
    
    def analyze_extracted_text(self, ocr_result: Dict[str, Any], user_query: str) -> Dict[str, Any]:
        """
        Prepare OCR result and user query for AI analysis
        
        Args:
            ocr_result: Result from extract_text_from_image
            user_query: User's question about the image
            
        Returns:
            Dictionary formatted for AI analysis
        """
        if 'error' in ocr_result:
            return ocr_result
        
        analysis_context = {
            'type': 'image_ocr_analysis',
            'extracted_text': ocr_result['extracted_text'],
            'user_query': user_query,
            'image_info': ocr_result['image_info'],
            'high_confidence_segments': ocr_result['high_confidence_segments'],
            'languages_detected': ocr_result['languages_used'],
            'processing_stats': {
                'total_segments': ocr_result['total_segments'],
                'high_confidence_count': ocr_result['high_confidence_count']
            }
        }
        
        return analysis_context
    
    def get_supported_languages(self) -> Dict[str, str]:
        """
        Get list of supported OCR languages
        
        Returns:
            Dictionary mapping language codes to language names
        """
        return {
            'eng': 'English',
            'jpn': 'Japanese',
            'chi_sim': 'Chinese (Simplified)',
            'chi_tra': 'Chinese (Traditional)',
            'kor': 'Korean',
            'fra': 'French',
            'deu': 'German',
            'spa': 'Spanish',
            'rus': 'Russian',
            'ara': 'Arabic'
        }