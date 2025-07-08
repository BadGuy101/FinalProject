# engines/threat_detector.py

import psutil
import logging
import numpy as np
from typing import Dict, List, Union
from datetime import datetime

class ThreatDetector:
    """
    Enhanced threat detector with multi-threat support and improved feature extraction.
    """
    
    THREAT_FEATURES = {
        'malware': ['cpu_usage', 'memory_usage', 'threads', 'connections', 'handles', 'io_operations'],
        'adware': ['network_connections', 'dlls_loaded', 'registry_changes', 'popup_windows'],
        'ransomware': ['file_operations', 'encryption_apis', 'network_activity', 'process_injection'],
        'malicious_website': ['js_functions', 'dom_changes', 'network_requests', 'iframe_usage']
    }

    def __init__(self, model_manager, security_manager):
        self.model_manager = model_manager
        self.security_manager = security_manager
        self.logger = logging.getLogger("ML_Engine.ThreatDetector")
        self.feature_cache = {}  # For tracking process features over time

    def analyze_process(self, pid: int, threat_type: str = None) -> Dict[str, Union[str, int]]:
        """
        Enhanced process analysis with threat type specialization.
        """
        try:
            if not psutil.pid_exists(pid):
                return {'status': 'error', 'message': 'Process not found', 'timestamp': datetime.now().isoformat()}

            # Get appropriate features based on threat type
            features = self._extract_features(pid, threat_type)
            
            # Get prediction from appropriate model
            is_malicious = self._evaluate_threat(features, threat_type)
            
            if is_malicious:
                self.security_manager.protect_process(pid)
                return {
                    'status': 'protected',
                    'pid': pid,
                    'threat_type': threat_type or 'generic',
                    'confidence': self.model_manager.predict_proba(features),
                    'timestamp': datetime.now().isoformat()
                }

            return {
                'status': 'clean',
                'pid': pid,
                'threat_type': threat_type or 'generic',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error analyzing process {pid}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _evaluate_threat(self, features: np.ndarray, threat_type: str = None) -> bool:
        """
        Evaluate threat using appropriate models based on threat type.
        """
        try:
            # Use threat-specific model if available
            if threat_type and threat_type in self.model_manager.best_models:
                prediction = self.model_manager.predict(features, threat_type=threat_type)
                return prediction == 1
            
            # Fallback to anomaly detection for unknown types
            anomaly_models = ['isolation_forest', 'one_class_svm']
            predictions = [
                self.model_manager.predict(features, model_name=name) == -1
                for name in anomaly_models
            ]
            
            return any(predictions)
        except Exception as e:
            self.logger.error(f"Threat evaluation failed: {e}")
            return False

    def _extract_features(self, pid: int, threat_type: str = None) -> List[float]:
        """
        Enhanced feature extraction with threat-specific features.
        """
        try:
            proc = psutil.Process(pid)
            features = []
            
            # Common features for all threat types
            with proc.oneshot():
                common_features = [
                    proc.cpu_percent(interval=0.1),
                    proc.memory_percent(),
                    proc.num_threads(),
                    len(proc.connections(kind='inet')),
                    len(proc.open_files()),
                    proc.nice()
                ]
                features.extend(common_features)
                
                # Threat-specific features
                if threat_type == 'malware':
                    features.extend([
                        len(proc.memory_maps()),
                        proc.num_handles(),
                        proc.io_counters().read_count if proc.io_counters() else 0
                    ])
                elif threat_type == 'adware':
                    features.extend([
                        len([c for c in proc.connections() if c.status == 'ESTABLISHED']),
                        len(proc.environ()),
                        len(proc.children())
                    ])
                elif threat_type == 'ransomware':
                    features.extend([
                        proc.io_counters().write_count if proc.io_counters() else 0,
                        len([f for f in proc.open_files() if f.path.endswith('.encrypted')]),
                        1 if any('crypt' in d.dll.lower() for d in proc.memory_maps()) else 0
                    ])
                    
            # Add temporal features if we have history
            if pid in self.feature_cache:
                prev_features = self.feature_cache[pid]
                features.extend([
                    features[0] - prev_features[0],  # CPU delta
                    features[1] - prev_features[1],  # Memory delta
                    features[3] - prev_features[3]   # Connection delta
                ])
                
            # Update cache
            self.feature_cache[pid] = common_features
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            self.logger.debug(f"Error extracting features: {e}")
            return np.zeros(10, dtype=np.float32)  # Return zero array on error

    def scan_file(self, file_features: List[float], threat_type: str = None) -> Dict[str, Union[str, float]]:
        """
        Enhanced file scanning with threat type specialization.
        """
        try:
            features_array = np.array(file_features, dtype=np.float32).reshape(1, -1)
            
            if threat_type and threat_type in self.model_manager.best_models:
                prediction = self.model_manager.predict(features_array, threat_type=threat_type)
                proba = self.model_manager.predict_proba(features_array)
            else:
                prediction = self.model_manager.predict(features_array)
                proba = 0.95 if prediction == 1 else 0.05
                
            return {
                'verdict': 'malicious' if prediction == 1 else 'benign',
                'confidence': float(proba),
                'threat_type': threat_type or 'generic',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"File scan failed: {e}")
            return {
                'verdict': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def batch_scan(self, pids: List[int]) -> Dict[int, Dict]:
        """Scan multiple processes efficiently"""
        results = {}
        for pid in pids:
            results[pid] = self.analyze_process(pid)
        return results