"""
Performance monitoring and optimization utilities
"""
import time
import psutil
import streamlit as st
from functools import wraps
from typing import Dict, Any, Optional
from utils.logger import enterprise_logger

class PerformanceMonitor:
    """Monitor application performance metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.thresholds = {
            'response_time': 5.0,  # seconds
            'memory_usage': 80.0,  # percentage
            'cpu_usage': 80.0      # percentage
        }
    
    def performance_timer(self, operation_name: str):
        """Decorator to time function execution"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    duration = time.time() - start_time
                    
                    # Log performance metrics
                    enterprise_logger.log_performance(
                        operation_name,
                        duration,
                        function=func.__name__,
                        args_count=len(args),
                        kwargs_count=len(kwargs)
                    )
                    
                    # Check for performance issues
                    if duration > self.thresholds['response_time']:
                        enterprise_logger.logger.warning(
                            f"SLOW_OPERATION: {operation_name} took {duration:.2f}s"
                        )
                    
                    # Store metrics
                    if operation_name not in self.metrics:
                        self.metrics[operation_name] = []
                    
                    self.metrics[operation_name].append({
                        'duration': duration,
                        'timestamp': time.time(),
                        'success': True
                    })
                    
                    return result
                    
                except Exception as e:
                    duration = time.time() - start_time
                    enterprise_logger.log_error(e, f"Performance monitoring for {operation_name}")
                    
                    # Store failed operation metrics
                    if operation_name not in self.metrics:
                        self.metrics[operation_name] = []
                    
                    self.metrics[operation_name].append({
                        'duration': duration,
                        'timestamp': time.time(),
                        'success': False,
                        'error': str(e)
                    })
                    
                    raise
            return wrapper
        return decorator
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system performance metrics"""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            metrics = {
                'memory_usage_percent': memory.percent,
                'memory_available_gb': memory.available / (1024**3),
                'memory_total_gb': memory.total / (1024**3),
                'cpu_usage_percent': cpu_percent,
                'cpu_count': psutil.cpu_count(),
                'timestamp': time.time()
            }
            
            # Check thresholds
            if memory.percent > self.thresholds['memory_usage']:
                enterprise_logger.logger.warning(f"HIGH_MEMORY_USAGE: {memory.percent:.1f}%")
            
            if cpu_percent > self.thresholds['cpu_usage']:
                enterprise_logger.logger.warning(f"HIGH_CPU_USAGE: {cpu_percent:.1f}%")
            
            return metrics
            
        except Exception as e:
            enterprise_logger.log_error(e, "System metrics collection")
            return {}
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for all operations"""
        summary = {}
        
        for operation, metrics_list in self.metrics.items():
            if not metrics_list:
                continue
            
            successful_ops = [m for m in metrics_list if m.get('success', True)]
            failed_ops = [m for m in metrics_list if not m.get('success', True)]
            
            if successful_ops:
                durations = [m['duration'] for m in successful_ops]
                summary[operation] = {
                    'total_calls': len(metrics_list),
                    'successful_calls': len(successful_ops),
                    'failed_calls': len(failed_ops),
                    'avg_duration': sum(durations) / len(durations),
                    'min_duration': min(durations),
                    'max_duration': max(durations),
                    'success_rate': len(successful_ops) / len(metrics_list) * 100
                }
        
        return summary
    
    def clear_metrics(self):
        """Clear stored performance metrics"""
        self.metrics.clear()
        enterprise_logger.logger.info("Performance metrics cleared")

# Global performance monitor
performance_monitor = PerformanceMonitor()

# Decorators for common operations
def monitor_file_processing(func):
    return performance_monitor.performance_timer("file_processing")(func)

def monitor_database_query(func):
    return performance_monitor.performance_timer("database_query")(func)

def monitor_ai_analysis(func):
    return performance_monitor.performance_timer("ai_analysis")(func)