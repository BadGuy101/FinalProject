import os
import subprocess
import hashlib
import hmac
import base64
import logging
import psutil
import secrets
from datetime import datetime
from collections import defaultdict
from .driver_comm import DriverInterface
from collections import defaultdict
from .exceptions import DriverError
from utils.audit_logger import AuditLogger


class SecurityManager:
    """Advanced security manager for the application itself"""

    def __init__(self):
        self.driver = DriverInterface()
        self.process_monitor = None  # Will be initialized later
        self.protected_processes = set()
        self.secret_key = self._generate_secret_key()
        self.session_tokens = {}
        self.failed_attempts = defaultdict(int)
        self.locked_ips = set()

    def initialize_monitors(self):
        from .system_monitor import AdvancedSystemMonitor
        self.process_monitor = AdvancedSystemMonitor()

    def initialize(self):
        try:
            self.driver.connect()
            AuditLogger.log("Driver connected", "SYSTEM")
        except DriverError as e:
            AuditLogger.log(f"Driver connection failed: {e}", "ERROR")

    def protect_process(self, pid):
        if not self.process_monitor or not self.process_monitor.validate_pid(pid):
            return False

        try:
            self.driver.protect_process(pid)
            self.protected_processes.add(pid)
            AuditLogger.log(f"Protected process {pid}", "PROTECTION")
            return True
        except DriverError as e:
            AuditLogger.log(f"Protection failed for {pid}: {e}", "ERROR")
            return False
            
    def scan_process(self, pid):
        if pid in self.protected_processes:
            AuditLogger.log(f"Scan blocked for protected process {pid}", "WARNING")
            return []
            
        regions = self.process_monitor.get_memory_regions(pid)
        results = []
        for start, size in regions:
            try:
                # Scan for common malware patterns
                result = self.driver.scan_memory(pid, start, size, b"\x90\x90\x90")
                results.extend(self._parse_scan_results(result))
            except DriverError as e:
                AuditLogger.log(f"Scan failed: {e}", "ERROR")
        return results
        
    def _parse_scan_results(self, raw_data):
        # Convert raw bytes to address list
        return [int.from_bytes(raw_data[i:i+8], 'little') 
                for i in range(0, len(raw_data), 8)]
    

    def _generate_secret_key(self):
        """Generate a secure secret key for the session"""
        return secrets.token_hex(32)
    
    def generate_session_token(self, user_id="admin"):
        """Generate a secure session token"""
        token = secrets.token_urlsafe(32)
        self.session_tokens[token] = {
            'user_id': user_id,
            'created': datetime.now(),
            'last_used': datetime.now()
        }
        return token
    
    def validate_session_token(self, token):
        """Validate a session token"""
        if token in self.session_tokens:
            session = self.session_tokens[token]
            if (datetime.now() - session['last_used']).seconds < 3600:  # 1 hour timeout
                session['last_used'] = datetime.now()
                return True
            else:
                del self.session_tokens[token]
        return False
    
    def encrypt_data(self, data):
        """Simple data encryption using HMAC"""
        if isinstance(data, str):
            data = data.encode()
        signature = hmac.new(self.secret_key.encode(), data, hashlib.sha256).hexdigest()
        return base64.b64encode(data).decode() + "." + signature
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data encrypted with encrypt_data"""
        try:
            data_b64, signature = encrypted_data.split('.')
            data = base64.b64decode(data_b64)
            expected_signature = hmac.new(self.secret_key.encode(), data, hashlib.sha256).hexdigest()
            if hmac.compare_digest(signature, expected_signature):
                return data.decode()
        except:
            pass
        return None
    def contain_process(self, pid: int, reason: str = "Unknown"):
        try:
            proc = psutil.Process(pid)
            proc.suspend()  # Temporarily pause
            proc.terminate()  # Attempt graceful termination
            proc.wait(timeout=3)
            logging.warning(f"[CONTAINMENT] Process {pid} ({proc.name()}) terminated due to: {reason}")
            return True
        except Exception as e:
            logging.error(f"[CONTAINMENT FAILED] Could not contain PID {pid}: {e}")
            return False
    def enter_quarantine_mode(self, reason="Unspecified"):
        """System-wide lockdown for critical threat response."""
        logging.critical(f"[QUARANTINE MODE] Triggered: {reason}")

        # 1. Drop flag for GUI
        try:
            with open("lockdown.flag", "w") as f:
                f.write(f"Quarantine Triggered: {reason}")
        except Exception as e:
            logging.error(f"Failed to write lockdown flag: {e}")

        # 2. Kill non-essential processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] not in ['explorer.exe', 'python.exe', 'AdvoShield.exe']:
                    proc.terminate()
            except Exception:
                continue

        # 3. Block outbound network (Windows)
        try:
            subprocess.run("netsh advfirewall set allprofiles state on", shell=True)
            subprocess.run("netsh advfirewall set allprofiles blockall outbound", shell=True)
        except Exception as e:
            logging.error(f"Failed to block network: {e}")