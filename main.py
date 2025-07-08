# main.py

# Import necessary modules
import os
import logging
import signal
import sys
import unittest
import traceback
import psutil
import threading
from typing import Dict, Any, Optional
from threading import Event, Lock
from config.logger import get_logger
from config.settings import (
    LOG_LEVEL,
    DEFAULT_DATASET_PATH,
    NETWORK_INTERFACE,
    MAX_LOG_BYTES,
    LOG_BACKUP_COUNT,
)
from utils.audit_logger import AuditLogger
from core.dependency_manager import AdvancedDependencyManager
from core.system_monitor import AdvancedSystemMonitor
from core.security_manager import SecurityManager
from core.threat_intelligence import AdvancedThreatIntelligence
from core.quarantine_manager import QuarantineManager
from engines.file_scanner import AdvancedFileScanner
from engines.ml_engine import AdvancedMLEngine
from core.network_sniffer import NetworkSniffer
from core.realtime_file_watcher import start_watching
from core.driver_comm import DriverInterface
from logging.handlers import RotatingFileHandler
from engines.model_manager import ModelManager

sys.stdout.reconfigure(encoding='utf-8')

# Initialize logger with rotation
logger = get_logger("AdvoShield")
logger.addHandler(
    RotatingFileHandler(
        "advoshield.log",
        maxBytes=MAX_LOG_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
)
audit_logger = AuditLogger()

# Graceful shutdown event
shutdown_event = Event()
thread_lock = Lock()

# Optional components (fail gracefully)
NetworkAnalyzer: Optional[Any] = None
try:
    from core.network_analyzer import NetworkAnalyzer
except ImportError:
    logger.warning("NetworkAnalyzer not available (optional module)")

def initialize_components() -> Dict[str, Any]:
    """Initialize all system components with dependency injection."""
    logger.info("Initializing system components...")
    components = {}

    try:
        components["system_monitor"] = AdvancedSystemMonitor()
        components["security_manager"] = SecurityManager()
        components["threat_intel"] = AdvancedThreatIntelligence()

        ml_engine = AdvancedMLEngine()
        try:
            if ml_engine.load_dataset(DEFAULT_DATASET_PATH, label_column="Hash"):
                if ml_engine.preprocess_dataset():
                    ml_engine.train_all_models()
        except Exception as e:
            logger.error(f"ML Engine degraded: {e}")
            ml_engine = None
        components["ml_engine"] = ml_engine

        components["file_scanner"] = AdvancedFileScanner()
        components["quarantine_manager"] = QuarantineManager(
            file_scanner=components["file_scanner"]
        )

        components["network_sniffer"] = NetworkSniffer(
            interface=NETWORK_INTERFACE,
            stop_event=shutdown_event,
        )
        components["network_sniffer"].start_capture()

        components["network_analyzer"] = NetworkAnalyzer() if NetworkAnalyzer else None

        return components

    except Exception as e:
        logger.critical(f"Component initialization failed: {e}", exc_info=True)
        audit_logger.log_event("INIT_FAILURE", traceback.format_exc())
        raise

def shutdown_handler(signum, frame):
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    logger.info("Shutting down AdvoShield...")
    shutdown_event.set()
    sys.exit(0)

if "--test" in sys.argv:
    from tests import load_all_tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(load_all_tests())
    sys.exit(0 if result.wasSuccessful() else 1)

def main() -> int:
    """Main application entry point with lifecycle management."""
    components = {}
    watcher_thread = None

    try:
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        AdvancedDependencyManager().check_and_install_all()

        driver = DriverInterface()
        try:
            driver.connect()
            ping = driver.send_ping()
            if not ping.is_ok():
                logger.warning("Driver interface unresponsive (running in user mode only)")
            else:
                components["driver_interface"] = driver
        except Exception as e:
            logger.warning(f"Driver unavailable: {e}")

        components.update(initialize_components())
        components["security_manager"].initialize_monitors()

        watcher_thread = threading.Thread(
            target=start_watching,
            args=(
                components["file_scanner"],
                components["quarantine_manager"],
                shutdown_event,
            ),
            daemon=True,
        )
        watcher_thread.start()

        """# Launch GUI
        from gui.gui import AdvoShieldGUI
        components.pop("network_analyzer", None)
        gui = AdvoShieldGUI(components)
        gui.run()  # Assuming .run() starts the GUI loop
"""
        return 0

    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        audit_logger.log_event("FATAL_ERROR", traceback.format_exc())
        return 1

    finally:
        shutdown_event.set()
        if watcher_thread:
            try:
                watcher_thread.join(timeout=5)
            except Exception:
                logger.warning("Watcher thread did not exit cleanly.")
        logger.info("AdvoShield shutdown complete")

if __name__ == "__main__":
    sys.exit(main())
