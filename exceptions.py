
class DriverError(Exception):
    def __init__(self, message, *args):
        super().__init__(message, *args)

class QuarantineError(Exception):
    """Exception raised when file quarantine operation fails."""
    def __init__(self, message="Quarantine operation failed"):
        super().__init__(message)

class MLModelError(Exception):
    """Exception raised for issues with ML model operations."""
    def __init__(self, message="Machine learning model encountered an error"):
        super().__init__(message)

class RegistryError(Exception):
    """Exception raised for registry protection-related problems."""
    def __init__(self, message="Registry access or deletion failed"):
        super().__init__(message)

class DependencyError(Exception):
    """Exception raised during dependency validation or loading."""
    def __init__(self, message="Missing or invalid system dependency"):
        super().__init__(message)

class ConfigurationError(Exception):
    """Exception raised when application configuration is invalid or missing."""
    def __init__(self, message="Configuration error"):
        super().__init__(message)

class ScanEngineError(Exception):
    """Exception raised by scanning engine on processing failure."""
    def __init__(self, message="File scanning error"):
        super().__init__(message)
