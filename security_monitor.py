# core/security_monitor.py
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Callable
from config.logger import logger
from core.quarantine_manager import QuarantineManager
from engines.file_scanner import AdvancedFileScanner
from engines.ml_engine import AdvancedMLEngine
from utils.audit_logger import AuditLogger
from core.autorun_monitor import AutorunMonitor
from utils.notifications import notify_user
from utils.notifications import notify_user
from core.registry_protector import RegistryProtector

class AdvancedSecurityMonitor:
    """
    Advanced security monitoring system with real-time threat detection,
    policy enforcement, and automated response capabilities.
    """

    def __init__(self):
        self.autorun_monitor = AutorunMonitor()
        self.policies: List[Dict] = []
        self.threats_detected: List[Dict] = []
        self.quarantine = QuarantineManager()
        self.file_scanner = AdvancedFileScanner()
        self.ml_engine = AdvancedMLEngine()
        self.audit_logger = AuditLogger()
        self.registry_protector = RegistryProtector()
        self._monitoring_active = False
        self._monitor_thread = None
        self._callbacks: List[Callable] = []

        # Load default policies
        self._load_default_policies()


    def detect_and_contain_suspicious_processes(self):
        suspicious = self.get_suspicious_process_metrics()
        for proc in suspicious.get("suspicious_processes", []):
            proc_hash = self._calculate_process_hash(proc['pid'])  # If implemented
            if self.threat_intel.is_known_hash(proc_hash):
                self.security_manager.contain_process(proc['pid'], reason="Known malicious process")

    def check_autorun_threats(self):
        """Check registry and startup folder for persistence threats"""
        try:
            result = self.autorun_monitor.scan_autoruns()
            threats = []
            for entry in result.get("registry_hits", []):
                threats.append(f"🪟 Registry: {entry['name']} -> {entry['value']}")
            for file_path in result.get("startup_hits", []):
                threats.append(f"🗂️ Startup File: {file_path}")
            return threats
        except Exception as e:
            logging.error(f"[AutorunMonitor] Error: {e}")
            return []


    

    def scan_file_and_alert(self, file_path):
        result = self.file_scanner.scan_file(file_path)
        if result["verdict"] != "benign":
            notify_user("🚨 Threat Detected", f"{result['verdict'].upper()} in file: {file_path}")
            self.quarantine_manager.quarantine_file(file_path)


    def _load_default_policies(self) -> None:
        """Initialize with default security policies"""
        self.policies = [
            {
                'id': 'POL-001',
                'name': 'High Risk File Execution',
                'severity': 'critical',
                'action': 'quarantine',
                'conditions': {'threat_level': '>= 0.8'}
            },
            {
                'id': 'POL-002',
                'name': 'Suspicious Network Activity',
                'severity': 'high',
                'action': 'alert',
                'conditions': {'port': 'in [4444, 6666, 31337]'}
            }
        ]
        logger.info("Loaded default security policies")

    def add_policy(self, policy: Dict) -> None:
        """Add a new security policy with validation"""
        required_fields = {'id', 'name', 'severity', 'action', 'conditions'}
        if not all(field in policy for field in required_fields):
            raise ValueError("Policy missing required fields")
        
        self.policies.append(policy)
        self.audit_logger.log(
            action="policy_added",
            target=policy['id'],
            status="success",
            details=f"Added policy: {policy['name']}"
        )
        logger.info(f"Added new policy: {policy['name']}")

    def enforce_policies(self, event_data: Dict) -> Optional[Dict]:
        """
        Evaluate event against all policies and take appropriate action.
        Returns the action taken or None if no policy matched.
        """

        # 🔐 ✅ Quarantine trigger based on threat_level or known anomaly
        try:
            if event_data.get("threat_level", 0) >= 9:
                from core.security_manager import SecurityManager
                SecurityManager().enter_quarantine_mode(reason="Critical threat level detected")

            if event_data.get("source") == "registry_monitor" and "ms-settings" in event_data.get("persistence_key", ""):
                from core.security_manager import SecurityManager
                SecurityManager().enter_quarantine_mode(reason="UAC Bypass via Registry Detected")
        except Exception as e:
            logger.error(f"[Quarantine Trigger Failed] {e}")

        # ✅ Continue with existing policy evaluation
        for policy in self.policies:
            if self._matches_policy(event_data, policy):
                action = self._execute_policy_action(policy, event_data)
                
                self.threats_detected.append({
                    'timestamp': datetime.now().isoformat(),
                    'policy': policy['id'],
                    'event': event_data,
                    'action': action
                })

                self._notify_callbacks({
                    'type': 'policy_triggered',
                    'data': {
                        'policy': policy,
                        'event': event_data,
                        'action': action
                    }
                })
                return action
        return None


    def _matches_policy(self, event_data: Dict, policy: Dict) -> bool:
        """Check if event matches policy conditions"""
        try:
            for field, condition in policy['conditions'].items():
                if field not in event_data:
                    return False
                
                # Simple condition evaluation (can be enhanced with a rules engine)
                if isinstance(condition, str):
                    if condition.startswith('>='):
                        if not float(event_data[field]) >= float(condition[2:]):
                            return False
                    elif condition.startswith('in'):
                        items = eval(condition[3:])  # Simple list evaluation
                        if event_data[field] not in items:
                            return False
                    elif event_data[field] != condition:
                        return False
                elif event_data[field] != condition:
                    return False
            return True
        except Exception as e:
            logger.error(f"Policy evaluation error: {e}")
            return False

    def _execute_policy_action(self, policy: Dict, event_data: Dict) -> Dict:
        """Execute the action specified in the policy"""
        action = {
            'policy_id': policy['id'],
            'action': policy['action'],
            'timestamp': datetime.now().isoformat(),
            'status': 'pending'
        }

        try:
            if policy['action'] == 'quarantine' and 'file_path' in event_data:
                self.quarantine.quarantine_file(event_data['file_path'])
                action['status'] = 'completed'
                action['details'] = f"Quarantined {event_data['file_path']}"
                
            elif policy['action'] == 'alert':
                action['status'] = 'completed'
                action['details'] = f"Alert generated for {event_data}"
                
            elif policy['action'] == 'log':
                self.audit_logger.log(
                    action="policy_triggered",
                    target=policy['id'],
                    status="detected",
                    details=event_data
                )
                action['status'] = 'completed'
                
            logger.info(f"Executed policy action: {policy['action']}")
            return action
            
        except Exception as e:
            action['status'] = 'failed'
            action['error'] = str(e)
            logger.error(f"Failed to execute policy action: {e}")
            return action

    def start_monitoring(self) -> None:
        """Start continuous security monitoring in a background thread"""
        if self._monitoring_active:
            logger.warning("Monitoring already active")
            return

        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Started security monitoring")

    def stop_monitoring(self) -> None:
        """Stop the monitoring process"""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Stopped security monitoring")

    def _monitor_loop(self) -> None: 
        """Main monitoring loop that checks system state"""
        while self._monitoring_active:
            try:
                # ✅ Check for file system threats
                recent_files = self.file_scanner.get_recent_files()
                for file in recent_files:
                    scan_result = self.file_scanner.scan_file(file)
                    if scan_result['is_malicious']:
                        self.enforce_policies({
                            'file_path': file,
                            'threat_level': scan_result['threat_score'],
                            'scan_type': 'on_access'
                        })

                # ✅ Check for ML anomalies
                ml_results = self.ml_engine.check_system_anomalies()
                if ml_results['anomaly_detected']:
                    self.enforce_policies({
                        'anomaly_type': ml_results['anomaly_type'],
                        'confidence': ml_results['confidence'],
                        'source': 'ml_engine'
                    })

                # ✅ Check for suspicious registry entries
                registry_hits = self.registry_protector.scan_registry()
                if registry_hits:
                    for path, value in registry_hits:
                        logger.warning(f"[REGISTRY] Suspicious key: {path} → {value}")
                        self.enforce_policies({
                            'persistence_key': path,
                            'persistence_value': value,
                            'source': 'registry_monitor'
                        })

                time.sleep(10)  # Loop interval

            except Exception as e:
                logger.critical(f"Monitoring loop error: {e}")
                time.sleep(30)  # Recovery wait


    def register_callback(self, callback: Callable) -> None:
        """Register a callback for policy trigger events"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, event: Dict) -> None:
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Callback notification failed: {e}")

    def get_security_status(self) -> Dict:
        """Return current security status snapshot"""
        return {
            'active_policies': len(self.policies),
            'threats_detected': len(self.threats_detected),
            'last_scan': datetime.now().isoformat(),
            'monitoring_active': self._monitoring_active
        }

    def __del__(self):
        """Cleanup on instance destruction"""
        self.stop_monitoring()