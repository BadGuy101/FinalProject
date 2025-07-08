# config/logger.py
import logging
import os
from datetime import datetime
from typing import Optional
from config.settings import LOG_DIR, LOG_LEVEL

class AdvoShieldLogger:
    """Centralized logging system for AdvoShield"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize logging system"""
        self._ensure_log_dir()
        self._setup_root_logger()
        
    def _ensure_log_dir(self):
        """Ensure log directory exists"""
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
        except OSError as e:
            print(f"CRITICAL: Failed to create log directory: {e}")
            raise
    
    def _setup_root_logger(self):
        """Configure the root logger"""
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)-8s] %(name)-20s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # File handler (daily logs)
        log_file = os.path.join(LOG_DIR, f"advoshield_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.FileHandler(
            filename=log_file,
            mode='a',
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        
        # Configure root logger
        logging.basicConfig(
            level=LOG_LEVEL,
            handlers=[console_handler, file_handler]
        )
        
        logging.info("Logger system initialized")

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__). None returns root logger.
    """
    # Initialize logging system if not already done
    AdvoShieldLogger()
    return logging.getLogger(name)

# Create root logger instance for backward compatibility
logger = get_logger()