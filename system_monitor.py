import psutil
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque
from utils.helpers import validate_pid

from utils.notifications import notify_user
from engines.file_scanner import AdvancedFileScanner
from core.quarantine_manager import QuarantineManager
from collections import defaultdict, deque



class AdvancedSystemMonitor:
    """Comprehensive system monitoring with behavioral analysis"""
    def __init__(self, callback=None, file_scanner=None, quarantine_manager=None):
        self._callback = callback
        self.process_cache = {}
        self.baseline_metrics = {}
        self.process_history = defaultdict(list)
        self.network_history = defaultdict(list)
        self.file_integrity_db = {}
        self.registry_baseline = {}
        self.performance_metrics = deque(maxlen=1000)
        self._monitoring = False
        self._monitor_thread = None
        self.file_scanner = file_scanner
        self.quarantine_manager = quarantine_manager  # ✅ Fixed typo

        # Behavioral patterns
        self.suspicious_behaviors = {
            'rapid_file_creation': {'threshold': 10, 'timeframe': 60},
            'excessive_network_connections': {'threshold': 50, 'timeframe': 60},
            'high_cpu_usage': {'threshold': 90, 'timeframe': 300},
            'memory_injection': {'patterns': ['VirtualAllocEx', 'WriteProcessMemory']},
            'registry_bombing': {'threshold': 20, 'timeframe': 60}
        }

        # Adware/Malware indicators
        self.malware_indicators = {
            'process_names': [
                'ads', 'popup', 'banner', 'adware', 'malware', 'toolbar',
                'searchprotect', 'browsersafeguard', 'browserdefender',
                'speedupmypc', 'driver', 'updater', 'installer'
            ],
            'file_extensions': ['.tmp', '.temp', '.exe', '.scr', '.bat', '.cmd'],
            'registry_keys': [
                r'Software\Microsoft\Windows\CurrentVersion\Run',
                r'Software\Microsoft\Internet Explorer\Main',
                r'Software\Classes\CLSID'
            ],
            'network_patterns': [
                'ads.', 'analytics.', 'tracking.', 'metrics.',
                'doubleclick', 'googlesyndication', 'googleadservices'
            ]
        }

    

    def check_disk_health(self):
        """
        Simulate a disk health check (placeholder for SMART-based tools).
        """
        try:
            disk_usage = psutil.disk_usage('/')
            if disk_usage.percent > 90:
                self.logger.warning("Disk is almost full: %.2f%%", disk_usage.percent)
            # Future: Integrate with smartmontools or WMI for deeper analysis
        except Exception as e:
            self.logger.exception("Failed to check disk health: %s", e)

    
    def perform_resource_check(self):
        """
        Check system resource usage against thresholds and log if abnormal.
        """
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            if cpu_usage > 90:
                self.logger.warning("High CPU usage detected: %.2f%%", cpu_usage)
            if mem.percent > 90:
                self.logger.warning("High Memory usage detected: %.2f%%", mem.percent)
        except Exception as e:
            self.logger.exception("Failed to perform resource check: %s", e)


    

   

    def scan_file_and_alert(self, file_path):
        result = self.file_scanner.scan_file(file_path)
        if result["verdict"] != "benign":
            notify_user("🚨 Threat Detected", f"{result['verdict'].upper()} in file: {file_path}")
            self.quarantine_manager.quarantine_file(file_path)



    def collect_comprehensive_metrics(self):
        """Collect comprehensive system metrics"""
        try:
            # Basic system metrics
            cpu_times = psutil.cpu_times()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            boot_time = psutil.boot_time()
            
            # Process information
            processes = []
            for proc in psutil.process_iter([
                'pid', 'name', 'cpu_percent', 'memory_percent',
                'create_time', 'exe', 'cmdline', 'connections',
                'open_files', 'threads'
            ]):
                try:
                    proc_info = proc.info
                    proc_info['cpu_times'] = proc.cpu_times()._asdict()
                    proc_info['memory_info'] = proc.memory_info()._asdict()
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Network connections
            connections = []
            for conn in psutil.net_connections():
                try:
                    conn_info = {
                        'fd': conn.fd,
                        'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                        'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                        'laddr': conn.laddr._asdict() if conn.laddr else None,
                        'raddr': conn.raddr._asdict() if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    connections.append(conn_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # System-wide statistics
            net_io = psutil.net_io_counters()
            disk_io = psutil.disk_io_counters()
            
            metrics = {
                'timestamp': datetime.now(),
                'cpu': {
                    'percent': psutil.cpu_percent(interval=0.1),
                    'times': cpu_times._asdict(),
                    'count': psutil.cpu_count(),
                    'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
                },
                'memory': {
                    'virtual': memory._asdict(),
                    'swap': psutil.swap_memory()._asdict()
                },
                'disk': {
                    'usage': disk._asdict(),
                    'io': disk_io._asdict() if disk_io else {}
                },
                'network': {
                    'io': net_io._asdict(),
                    'connections': connections
                },
                'processes': processes,
                'system': {
                    'boot_time': boot_time,
                    'users': [u._asdict() for u in psutil.users()]
                }
            }
            
            # Store in performance history
            self.performance_metrics.append({
                'timestamp': metrics['timestamp'],
                'cpu_percent': metrics['cpu']['percent'],
                'memory_percent': metrics['memory']['virtual']['percent'],
                'disk_percent': metrics['disk']['usage']['percent'],
                'process_count': len(processes),
                'connection_count': len(connections)
            })
            
            return metrics
            
        except Exception as e:
            logging.error(f"Error collecting system metrics: {e}")
            return None
    
    def analyze_behavioral_patterns(self, current_metrics, historical_data):
        """Analyze behavioral patterns for anomalies"""
        anomalies = []
        
        if not current_metrics or not historical_data:
            return anomalies
        
        try:
            # Analyze process creation patterns
            current_processes = {p['pid']: p for p in current_metrics['processes']}
            if historical_data:
                last_processes = {p['pid']: p for p in historical_data[-1]['processes']} if historical_data[-1].get('processes') else {}
                new_processes = set(current_processes.keys()) - set(last_processes.keys())
                
                if len(new_processes) > self.suspicious_behaviors['rapid_file_creation']['threshold']:
                    anomalies.append({
                        'type': 'rapid_process_creation',
                        'severity': 'high',
                        'description': f'{len(new_processes)} new processes created rapidly',
                        'processes': [current_processes[pid]['name'] for pid in new_processes]
                    })
            
            # Analyze network connection patterns
            current_connections = current_metrics['network']['connections']
            if len(current_connections) > self.suspicious_behaviors['excessive_network_connections']['threshold']:
                anomalies.append({
                    'type': 'excessive_network_activity',
                    'severity': 'medium',
                    'description': f'{len(current_connections)} active network connections',
                    'connections': len(current_connections)
                })
            
            # Analyze CPU usage patterns
            if current_metrics['cpu']['percent'] > self.suspicious_behaviors['high_cpu_usage']['threshold']:
                anomalies.append({
                    'type': 'high_cpu_usage',
                    'severity': 'medium',
                    'description': f'CPU usage at {current_metrics["cpu"]["percent"]:.1f}%',
                    'cpu_percent': current_metrics['cpu']['percent']
                })
            
            # Analyze memory usage patterns
            if current_metrics['memory']['virtual']['percent'] > 90:
                anomalies.append({
                    'type': 'high_memory_usage',
                    'severity': 'medium',
                    'description': f'Memory usage at {current_metrics["memory"]["virtual"]["percent"]:.1f}%',
                    'memory_percent': current_metrics['memory']['virtual']['percent']
                })
            
        except Exception as e:
            logging.error(f"Error analyzing behavioral patterns: {e}")
        
        return anomalies
    
    def detect_process_injection(self, processes):
        """Detect potential process injection techniques"""
        suspicious_processes = []
        
        for proc in processes:
            try:
                # Check for suspicious process characteristics
                suspicion_score = 0
                reasons = []
                
                # Check process name
                proc_name = proc.get('name', '').lower()
                for indicator in self.malware_indicators['process_names']:
                    if indicator in proc_name:
                        suspicion_score += 3
                        reasons.append(f'Suspicious name: {indicator}')
                
                # Check command line arguments
                cmdline = proc.get('cmdline', [])
                if cmdline:
                    cmdline_str = ' '.join(cmdline).lower()
                    injection_keywords = ['inject', 'hollow', 'reflective', 'allocex', 'writeprocessmemory']
                    for keyword in injection_keywords:
                        if keyword in cmdline_str:
                            suspicion_score += 5
                            reasons.append(f'Injection keyword: {keyword}')
                
                # Check resource usage
                if proc.get('cpu_percent', 0) > 50 and proc.get('memory_percent', 0) > 30:
                    suspicion_score += 2
                    reasons.append('High resource usage')
                
                # Check thread count (potential injection indicator)
                if proc.get('threads', 0) > 100:
                    suspicion_score += 2
                    reasons.append('High thread count')
                
                if suspicion_score >= 5:
                    suspicious_processes.append({
                        'process': proc,
                        'suspicion_score': suspicion_score,
                        'reasons': reasons,
                        'severity': 'high' if suspicion_score >= 8 else 'medium'
                    })
                    
            except Exception as e:
                logging.error(f"Error analyzing process {proc.get('name', 'unknown')}: {e}")
        
        return suspicious_processes
    
    def monitor_registry_changes(self):
        """Monitor Windows registry for suspicious changes"""
        changes = []
        try:
            for hkey_name, hkey in [
                ('HKEY_CURRENT_USER', winreg.HKEY_CURRENT_USER),
                ('HKEY_LOCAL_MACHINE', winreg.HKEY_LOCAL_MACHINE)
            ]:
                for subkey_path in self.malware_indicators['registry_keys']:
                    try:
                        with winreg.OpenKey(hkey, subkey_path) as key:
                            i = 0
                            current_values = {}
                            while True:
                                try:
                                    name, value, reg_type = winreg.EnumValue(key, i)
                                    current_values[name] = (value, reg_type)
                                    i += 1
                                except WindowsError:
                                    break
                            
                            # Compare with baseline
                            baseline_key = f"{hkey_name}\\{subkey_path}"
                            if baseline_key in self.registry_baseline:
                                baseline_values = self.registry_baseline[baseline_key]
                                
                                # Check for new values
                                for name, (value, reg_type) in current_values.items():
                                    if name not in baseline_values:
                                        changes.append({
                                            'type': 'registry_addition',
                                            'key': baseline_key,
                                            'name': name,
                                            'value': value,
                                            'severity': self._assess_registry_change_severity(name, value)
                                        })
                                
                                # Check for modified values
                                for name, (value, reg_type) in current_values.items():
                                    if name in baseline_values and baseline_values[name] != (value, reg_type):
                                        changes.append({
                                            'type': 'registry_modification',
                                            'key': baseline_key,
                                            'name': name,
                                            'old_value': baseline_values[name][0],
                                            'new_value': value,
                                            'severity': self._assess_registry_change_severity(name, value)
                                        })
                            else:
                                # First time seeing this key, establish baseline
                                self.registry_baseline[baseline_key] = current_values
                                
                    except Exception as e:
                        logging.debug(f"Could not access registry key {subkey_path}: {e}")
        except ImportError:
            # Not on Windows
            pass
        except Exception as e:
            logging.error(f"Error monitoring registry: {e}")
        
        return changes
    
    def _assess_registry_change_severity(self, name, value):
        """Assess the severity of a registry change"""
        name_lower = name.lower()
        value_str = str(value).lower()
        
        # High severity indicators
        high_severity_patterns = [
            'run', 'startup', 'explorer', 'shell', 'browser',
            'homepage', 'searchurl', 'proxy'
        ]
        
        for pattern in high_severity_patterns:
            if pattern in name_lower or pattern in value_str:
                return 'high'
        
        # Check for suspicious executables
        if value_str.endswith('.exe') or 'temp' in value_str or 'appdata' in value_str:
            return 'medium'
        
        return 'low'
    def start_monitoring(self,callback=None):
        self._monitoring = True
        self._cllback = callback
        """Starts system monitoring in a background thread."""
        if self._monitoring:
            logging.warning("System monitoring already running.")
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logging.info("🟢 System monitoring started.")

    def stop_monitoring(self):
        """Stops system monitoring cleanly."""
        if not self._monitoring:
            logging.warning("System monitoring is not running.")
            return

        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        logging.info("🔴 System monitoring stopped.")

    def _monitor_loop(self):
        """Background thread for periodic monitoring."""
        while self._monitoring:
            try:
                # 🔁 Add calls to any of your existing periodic check methods
                self.perform_resource_check()   # example method
                self.check_disk_health()        # example method
                # sleep between cycles
                time.sleep(5)
            except Exception as e:
                logging.error(f"Monitoring loop error: {e}")
                time.sleep(10)  # wait before retrying
        if self._callback:
            try:
                self._callback(system_metrics)  # Or whatever data you want to send
            except Exception as e:
                logging.warning(f"Callback failed: {e}")
    