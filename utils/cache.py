"""
Enterprise caching system
"""
import hashlib
import json
import time
from typing import Any, Optional, Dict
import streamlit as st
from utils.logger import enterprise_logger

class EnterpriseCache:
    """Advanced caching system for enterprise applications"""
    
    def __init__(self):
        self.cache_key_prefix = "log_analysis_"
        self.default_ttl = 3600  # 1 hour
        
    def _generate_cache_key(self, key: str, **kwargs) -> str:
        """Generate consistent cache key"""
        key_data = f"{key}:{json.dumps(kwargs, sort_keys=True)}"
        cache_key = hashlib.md5(key_data.encode()).hexdigest()
        return f"{self.cache_key_prefix}{cache_key}"
    
    def _is_cache_valid(self, cache_data: Dict) -> bool:
        """Check if cached data is still valid"""
        if not cache_data or 'timestamp' not in cache_data:
            return False
        
        ttl = cache_data.get('ttl', self.default_ttl)
        age = time.time() - cache_data['timestamp']
        
        return age < ttl
    
    def cache_file_analysis(self, file_content_hash: str, analysis_params: Dict) -> Optional[Dict]:
        """Cache file analysis results"""
        cache_key = self._generate_cache_key("file_analysis", file_hash=file_content_hash, **analysis_params)
        
        if cache_key in st.session_state:
            cache_data = st.session_state[cache_key]
            if self._is_cache_valid(cache_data):
                return cache_data['result']
            else:
                del st.session_state[cache_key]
        
        return None
    
    def cache_database_query(self, query_hash: str, connection_params: Dict) -> Optional[Dict]:
        """Cache database query results"""
        cache_key = self._generate_cache_key("database_query", query_hash=query_hash, **connection_params)
        
        if cache_key in st.session_state:
            cache_data = st.session_state[cache_key]
            if self._is_cache_valid(cache_data):
                return cache_data['result']
            else:
                del st.session_state[cache_key]
        
        return None
    
    def get_ai_analysis_cache(self, logs_hash: str, model_params: Dict) -> Optional[Dict]:
        """Get cached AI analysis results"""
        cache_key = self._generate_cache_key("ai_analysis", logs_hash=logs_hash, **model_params)
        
        if cache_key in st.session_state:
            cache_data = st.session_state[cache_key]
            if self._is_cache_valid(cache_data):
                enterprise_logger.logger.info(f"Cache hit for AI analysis: {cache_key[:12]}...")
                return cache_data['result']
            else:
                # Remove expired cache
                del st.session_state[cache_key]
                enterprise_logger.logger.info(f"Cache expired for AI analysis: {cache_key[:12]}...")
        
        return None
    
    def set_ai_analysis_cache(self, logs_hash: str, model_params: Dict, result: Dict, ttl: int = None):
        """Cache AI analysis results"""
        cache_key = self._generate_cache_key("ai_analysis", logs_hash=logs_hash, **model_params)
        
        cache_data = {
            'result': result,
            'timestamp': time.time(),
            'ttl': ttl or self.default_ttl
        }
        
        st.session_state[cache_key] = cache_data
        enterprise_logger.logger.info(f"Cached AI analysis result: {cache_key[:12]}...")
    
    def get_file_processing_cache(self, file_hash: str) -> Optional[Dict]:
        """Get cached file processing results"""
        cache_key = self._generate_cache_key("file_processing", file_hash=file_hash)
        
        if cache_key in st.session_state:
            cache_data = st.session_state[cache_key]
            if self._is_cache_valid(cache_data):
                enterprise_logger.logger.info(f"Cache hit for file processing: {cache_key[:12]}...")
                return cache_data['result']
            else:
                del st.session_state[cache_key]
        
        return None
    
    def set_file_processing_cache(self, file_hash: str, result: Dict, ttl: int = None):
        """Cache file processing results"""
        cache_key = self._generate_cache_key("file_processing", file_hash=file_hash)
        
        cache_data = {
            'result': result,
            'timestamp': time.time(),
            'ttl': ttl or self.default_ttl
        }
        
        st.session_state[cache_key] = cache_data
        enterprise_logger.logger.info(f"Cached file processing result: {cache_key[:12]}...")
    
    def clear_expired_cache(self):
        """Clear all expired cache entries"""
        expired_keys = []
        
        for key in st.session_state.keys():
            if key.startswith(self.cache_key_prefix):
                cache_data = st.session_state[key]
                if not self._is_cache_valid(cache_data):
                    expired_keys.append(key)
        
        for key in expired_keys:
            del st.session_state[key]
        
        if expired_keys:
            enterprise_logger.logger.info(f"Cleared {len(expired_keys)} expired cache entries")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        cache_keys = [k for k in st.session_state.keys() if k.startswith(self.cache_key_prefix)]
        
        valid_count = 0
        expired_count = 0
        total_size = 0
        
        for key in cache_keys:
            cache_data = st.session_state[key]
            if self._is_cache_valid(cache_data):
                valid_count += 1
            else:
                expired_count += 1
            
            # Estimate size
            try:
                total_size += len(json.dumps(cache_data))
            except:
                pass
        
        return {
            'total_entries': len(cache_keys),
            'valid_entries': valid_count,
            'expired_entries': expired_count,
            'estimated_size_bytes': total_size,
            'hit_rate_percent': (valid_count / len(cache_keys) * 100) if cache_keys else 0
        }

# Global cache instance
enterprise_cache = EnterpriseCache()