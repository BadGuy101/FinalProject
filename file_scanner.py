import os
import numpy as np
import time
import struct
import hashlib
import psutil
import logging
from pathlib import Path
from core.threat_intelligence import AdvancedThreatIntelligence
from core.security_manager import SecurityManager


from utils.notifications import notify_user
from utils.feature_aggregator import aggregate_features




import os
import numpy as np
import time
import struct
import hashlib
import psutil
import logging
from pathlib import Path
from typing import Dict, List

from core.threat_intelligence import AdvancedThreatIntelligence
from core.security_manager import SecurityManager
from utils.notifications import notify_user

logger = logging.getLogger("AdvoShield.FileScanner")

class AdvancedFileScanner:
    """Comprehensive file scanning with multiple detection methods and threat classification"""
    
    THREAT_SIGNATURES = {
        'malware': [
            b'MZ', b'PE\x00\x00', b'This program cannot be run in DOS mode',
            b'CreateRemoteThread', b'VirtualAllocEx'
        ],
        'adware': [
            b'adserver', b'doubleclick', b'popunder', b'advert',
            b'tracking', b'analytics', b'googlesyndication'
        ],
        'ransomware': [
            b'AES', b'RSA', b'encrypt', b'decrypt', b'ransom',
            b'bitcoin', b'wallet', b'payment'
        ],
        'malicious_website': [
            b'eval(', b'unescape(', b'fromCharCode', b'iframe',
            b'document.cookie', b'window.location', b'XMLHttpRequest'
        ]
    }

    def __init__(self, ml_engine=None, security_manager=None, quarantine_manager=None):
        self.threat_intelligence = AdvancedThreatIntelligence()
        self.file_signatures = self._load_file_signatures()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.security_manager = security_manager
        self.ml_engine = ml_engine
        self.quarantine_manager = quarantine_manager
        self.logger = logger
        
        self.scan_stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'threat_breakdown': {t: 0 for t in self.THREAT_SIGNATURES.keys()},
            'false_positives': 0,
            'scan_time': 0
        }
        
        self.suspicious_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', 
            '.vbs', '.js', '.jar', '.ps1', '.docm', '.xlsm'
        }

    def scan_file_and_alert(self, file_path: str) -> Dict:
        """Enhanced scanning with threat classification"""
        result = self.scan_file(file_path)
        
        if result["verdict"] != "benign":
            threat_type = result.get("threat_type", "unknown")
            self.scan_stats['threat_breakdown'][threat_type] += 1
            
            notify_user(
                "🚨 Threat Detected",
                f"{threat_type.upper()} found in {file_path}\n"
                f"Confidence: {result.get('confidence', 0):.0%}"
            )
            
            if self.quarantine_manager:
                self.quarantine_manager.quarantine_file(file_path)
                
        return result

    def scan_file(self, file_path: str) -> Dict:
        """Enhanced scanning with threat classification"""
        start_time = time.time()
        self.scan_stats['total_scans'] += 1
        
        result = {
            'file_path': file_path,
            'file_size': 0,
            'file_hash': '',
            'threat_level': 0,
            'detections': [],
            'verdict': 'benign',
            'threat_type': 'unknown',
            'confidence': 0,
            'scan_time': 0,
            'timestamp': time.time()
        }

        try:
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result

            # Basic file info
            file_stat = os.stat(file_path)
            result.update({
                'file_size': file_stat.st_size,
                'modification_time': file_stat.st_mtime,
                'file_hash': self._calculate_file_hash(file_path)
            })

            # Threat intelligence lookup
            ti_result = self.threat_intelligence.lookup(result['file_hash'])
            if ti_result['is_malicious']:
                result.update({
                    'verdict': 'malicious',
                    'threat_type': ti_result['threat_type'],
                    'confidence': ti_result['confidence'],
                    'threat_level': 10
                })
                self._update_stats(result)
                return result

            # Content analysis
            with open(file_path, 'rb') as f:
                content = f.read(min(1024 * 1024, file_stat.st_size))  # Read up to 1MB

            # Signature detection
            sig_results = self._detect_threat_signatures(content)
            result['detections'].extend(sig_results)
            result['threat_level'] += sum(d['weight'] for d in sig_results)

            # Heuristic analysis
            heuristic_results = self.heuristic_analyzer.analyze_file(file_path)
            result['detections'].extend(heuristic_results)
            result['threat_level'] += sum(d.get('weight', 1) for d in heuristic_results)

            # File extension check
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in self.suspicious_extensions:
                result['detections'].append({
                    'type': 'suspicious_extension',
                    'description': f'Potentially dangerous extension: {file_ext}',
                    'severity': 'medium',
                    'weight': 2
                })
                result['threat_level'] += 2

            # ML analysis if available
            if self.ml_engine:
                features = self.extract_features(file_path)
                ml_result = self.ml_engine.scan_file(features)
                if ml_result['verdict'] == 'malicious':
                    result['threat_level'] += 5
                    result['ml_confidence'] = ml_result['confidence']

            # Final verdict
            if result['threat_level'] >= 8:  # Higher threshold to reduce false positives
                result.update({
                    'verdict': 'malicious',
                    'confidence': min(0.99, result['threat_level'] / 15)
                })
                # Determine most likely threat type
                threat_types = [d['threat_type'] for d in result['detections'] if 'threat_type' in d]
                if threat_types:
                    result['threat_type'] = max(set(threat_types), key=threat_types.count)
                else:
                    result['threat_type'] = self._infer_threat_type(file_path, content)

            self._update_stats(result)
            return result

        except Exception as e:
            result.update({
                'error': str(e),
                'scan_time': time.time() - start_time
            })
            logger.error(f"Error scanning file {file_path}: {e}")
            return result
        finally:
            result['scan_time'] = time.time() - start_time

    def _detect_threat_signatures(self, content: bytes) -> List[Dict]:
        """Detect threat-specific signatures in file content"""
        detections = []
        for threat_type, signatures in self.THREAT_SIGNATURES.items():
            for sig in signatures:
                if sig in content:
                    detections.append({
                        'type': 'signature_match',
                        'threat_type': threat_type,
                        'description': f'Matched {threat_type} signature',
                        'severity': 'high',
                        'weight': 5
                    })
        return detections

    def _infer_threat_type(self, file_path: str, content: bytes) -> str:
        """Infer threat type based on file characteristics"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Check for ransomware indicators
        if any(sig in content for sig in self.THREAT_SIGNATURES['ransomware']):
            return 'ransomware'
            
        # Check for adware indicators
        if any(sig in content for sig in self.THREAT_SIGNATURES['adware']):
            return 'adware'
            
        # Check for malicious website indicators
        if file_ext in ('.html', '.js', '.php') or \
           any(sig in content for sig in self.THREAT_SIGNATURES['malicious_website']):
            return 'malicious_website'
            
        # Default to malware for executable files
        if file_ext in ('.exe', '.dll', '.sys'):
            return 'malware'
            
        return 'unknown'

    def extract_features(self, file_path: str) -> List[float]:
        """Enhanced feature extraction for ML engine"""
        try:
            result = self.scan_file(file_path)
            features = [
                result.get('file_size', 0),
                len(result.get('detections', [])),
                result.get('threat_level', 0),
                int(result.get('verdict') == 'malicious'),
                len([d for d in result.get('detections', []) 
                    if d.get('severity') == 'high'])
            ]
            
            # Add threat type indicators
            for threat_type in self.THREAT_SIGNATURES.keys():
                features.append(
                    1 if result.get('threat_type') == threat_type else 0
                )
                
            return features
        except Exception:
            return [0] * (5 + len(self.THREAT_SIGNATURES))

    def _update_stats(self, result: Dict) -> None:
        """Update scan statistics"""
        if result['verdict'] == 'malicious':
            self.scan_stats['threats_detected'] += 1
            self.scan_stats['threat_breakdown'][result['threat_type']] += 1

  
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _signature_scan(self, file_path):
        """Signature-based scanning"""
        detections = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                file_content = f.read(1024 * 1024)  # Read first 1MB
                
                # Check against signatures
                for sig_name, signature in self.file_signatures.items():
                    if signature in file_content:
                        detections.append({
                            'type': 'signature_match',
                            'description': f'Matched signature: {sig_name}',
                            'severity': 'medium',
                            'signature': sig_name,
                            'weight': 3
                        })
                
                # Check YARA-like rules
                for rule in self.yara_rules:
                    matches = 0
                    for pattern in rule['patterns']:
                        if pattern in file_content:
                            matches += 1
                    
                    if (rule['condition'] == 'any' and matches > 0) or \
                       (rule['condition'] == 'all' and matches == len(rule['patterns'])):
                        detections.append({
                            'type': 'rule_match',
                            'description': f'Matched rule: {rule["name"]}',
                            'severity': 'high' if rule['weight'] >= 7 else 'medium',
                            'rule': rule['name'],
                            'weight': rule['weight']
                        })
                
        except Exception as e:
            logging.error(f"Error in signature scan for {file_path}: {e}")
        
        return detections
    
    def _behavioral_analysis(self, file_path):
        """Analyze file for suspicious behavioral indicators"""
        detections = []
        
        try:
            # Analyze PE file if possible
            if file_path.lower().endswith('.exe'):
                pe_results = self._analyze_pe_file(file_path)
                detections.extend(pe_results)
            
            # Check file metadata
            metadata_results = self._analyze_file_metadata(file_path)
            detections.extend(metadata_results)
            
        except Exception as e:
            logging.error(f"Error in behavioral analysis for {file_path}: {e}")
        
        return detections
    
    def _analyze_pe_file(self, file_path):
        """Analyze PE (Portable Executable) files"""
        detections = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return detections
                
                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return detections
                
                # Read COFF header
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    return detections
                
                # Analyze characteristics
                characteristics = struct.unpack('<H', coff_header[18:20])[0]
                
                if characteristics & 0x0001:  # Relocation info stripped
                    detections.append({
                        'type': 'pe_analysis',
                        'description': 'PE file has suspicious characteristics',
                        'severity': 'low',
                        'weight': 1
                    })
                
        except Exception as e:
            logging.debug(f"Error analyzing PE file {file_path}: {e}")
        
        return detections
    
    def _analyze_file_metadata(self, file_path):
        """Analyze file metadata for suspicious indicators"""
        detections = []
        
        try:
            stat_info = os.stat(file_path)
            file_name = os.path.basename(file_path).lower()
            
            # Check for suspicious file names
            suspicious_names = [
                'ads', 'popup', 'banner', 'toolbar', 'searchprotect',
                'browsersafeguard', 'speedupmypc', 'driverupdater'
            ]
            
            for sus_name in suspicious_names:
                if sus_name in file_name:
                    detections.append({
                        'type': 'suspicious_filename',
                        'description': f'Suspicious filename contains: {sus_name}',
                        'severity': 'medium',
                        'weight': 3
                    })
                    break
            
            # Check file size (very small or very large executables can be suspicious)
            if file_path.lower().endswith('.exe'):
                if stat_info.st_size < 1024:  # Less than 1KB
                    detections.append({
                        'type': 'suspicious_size',
                        'description': 'Executable file is unusually small',
                        'severity': 'low',
                        'weight': 1
                    })
                elif stat_info.st_size > 100 * 1024 * 1024:  # Greater than 100MB
                    detections.append({
                        'type': 'suspicious_size',
                        'description': 'Executable file is unusually large',
                        'severity': 'low',
                        'weight': 1
                    })
            
            # Check modification time (files modified very recently might be suspicious)
            if time.time() - stat_info.st_mtime < 3600:  # Modified within last hour
                detections.append({
                    'type': 'recent_modification',
                    'description': 'File was modified recently',
                    'severity': 'low',
                    'weight': 1
                })
                
        except Exception as e:
            logging.debug(f"Error analyzing metadata for {file_path}: {e}")
        
        return detections
    
    def scan_directory(self, directory_path, recursive=True, file_filter=None):
        """Scan entire directory for threats"""
        results = {
            'directory': directory_path,
            'total_files': 0,
            'scanned_files': 0,
            'threats_found': 0,
            'scan_results': [],
            'scan_time': 0
        }
        
        start_time = time.time()
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Apply file filter if provided
                        if file_filter and not file_filter(file_path):
                            continue
                        
                        results['total_files'] += 1
                        
                        # Scan file
                        scan_result = self.scan_file(file_path)
                        results['scan_results'].append(scan_result)
                        results['scanned_files'] += 1
                        
                        if scan_result['is_malicious']:
                            results['threats_found'] += 1
            else:
                # Scan only files in the specified directory
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    
                    if os.path.isfile(file_path):
                        if file_filter and not file_filter(file_path):
                            continue
                        
                        results['total_files'] += 1
                        
                        scan_result = self.scan_file(file_path)
                        results['scan_results'].append(scan_result)
                        results['scanned_files'] += 1
                        
                        if scan_result['is_malicious']:
                            results['threats_found'] += 1
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            results['error'] = str(e)
            logging.error(f"Error scanning directory {directory_path}: {e}")
        
        return results


    def extract_features(self, file_path):
        """Extract numeric feature vector from a file for ML engine"""
        try:
            result = self.scan_file(file_path)
            return [
                result.get('file_size', 0),
                len(result.get('detections', [])),
                result.get('threat_level', 0),
                int(result.get('is_malicious', False))
            ]
        except Exception:
            return [0, 0, 0, 0]
    def is_suspicious(self, file_path, threshold=5):
        """Boolean wrapper for is_malicious logic"""
        result = self.scan_file(file_path)
        return result.get('is_malicious', False), result
    def predict_with_context(self, file_path, system_metrics, network_data, security_data):
        scan_result = self.scan_file(file_path)
        features = aggregate_features(scan_result, system_metrics, network_data, security_data)
        prediction = self.ml_engine.predict(features)
        return prediction


class HeuristicAnalyzer:
    """Advanced heuristic analysis engine"""
    
    def __init__(self):
        self.heuristic_rules = self._load_heuristic_rules()
        self.entropy_threshold = 7.5  # High entropy indicates possible packing/encryption
        
    def _load_heuristic_rules(self):
        """Load heuristic detection rules"""
        return [
            {
                'name': 'High_Entropy',
                'description': 'File has high entropy indicating possible packing',
                'check': self._check_entropy,
                'weight': 3
            },
            {
                'name': 'Suspicious_Strings',
                'description': 'Contains suspicious strings',
                'check': self._check_suspicious_strings,
                'weight': 4
            },
            {
                'name': 'Embedded_PE',
                'description': 'Contains embedded PE files',
                'check': self._check_embedded_pe,
                'weight': 5
            },
            {
                'name': 'Anti_Debug_Tricks',
                'description': 'Uses anti-debugging techniques',
                'check': self._check_anti_debug,
                'weight': 6
            }
        ]
    
    def analyze_file(self, file_path):
        """Perform comprehensive heuristic analysis"""
        detections = []
        
        try:
            for rule in self.heuristic_rules:
                try:
                    if rule['check'](file_path):
                        detections.append({
                            'type': 'heuristic',
                            'name': rule['name'],
                            'description': rule['description'],
                            'severity': 'medium',
                            'weight': rule['weight']
                        })
                except Exception as e:
                    logging.debug(f"Error applying heuristic rule {rule['name']}: {e}")
        
        except Exception as e:
            logging.error(f"Error in heuristic analysis for {file_path}: {e}")
        
        return detections
    
    def _check_entropy(self, file_path):
        """Check file entropy for possible packing"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024*1024, os.path.getsize(file_path)))  # Read up to 1MB
                
            if len(data) < 256:
                return False
            
            # Calculate Shannon entropy
            entropy = self._calculate_shannon_entropy(data)
            return entropy > self.entropy_threshold
            
        except Exception:
            return False
    
    def _calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                frequency = count / data_len
                entropy -= frequency * np.log2(frequency)
        
        return entropy
    
    def _check_suspicious_strings(self, file_path):
        """Check for suspicious strings in file"""
        suspicious_strings = [
            b'ads', b'popup', b'banner', b'advertisement', b'doubleclick',
            b'googlesyndication', b'analytics', b'tracking', b'toolbar',
            b'searchprotect', b'browsersafeguard', b'speedupmypc'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024*1024, os.path.getsize(file_path)))
            
            found_count = 0
            for sus_string in suspicious_strings:
                if sus_string.lower() in data.lower():
                    found_count += 1
            
            return found_count >= 2  # At least 2 suspicious strings
            
        except Exception:
            return False
    
    def _check_embedded_pe(self, file_path):
        """Check for embedded PE files"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024*1024, os.path.getsize(file_path)))
            
            # Look for PE signatures beyond the first one
            pe_signatures = [data.find(b'MZ'), data.find(b'PE\x00\x00')]
            pe_count = sum(1 for sig in pe_signatures if sig != -1)
            
            return pe_count > 1
            
        except Exception:
            return False
    
    def _check_anti_debug(self, file_path):
        """Check for anti-debugging techniques"""
        anti_debug_strings = [
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
            b'NtGlobalFlag', b'ProcessHeap', b'OutputDebugString'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024*1024, os.path.getsize(file_path)))
            
            for debug_string in anti_debug_strings:
                if debug_string in data:
                    return True
            
            return False
            
        except Exception:
            return False