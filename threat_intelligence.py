import requests
import logging
import re
import os
import pickle
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

class AdvancedThreatIntelligence:
    """Comprehensive threat intelligence system with multiple sources"""
    
    def __init__(self):
        self.sources = {
            'openphish': "https://openphish.com/feed.txt",
            'malware_domains': "https://mirror1.malwaredomains.com/files/domains.txt",
            'abuse_ch': "https://urlhaus.abuse.ch/downloads/csv_recent/",
            'phishtank': "http://data.phishtank.com/data/online-valid.csv",
            'alienvault': "https://reputation.alienvault.com/reputation.data"
        }
        
        self.threat_data = {
            'malicious_domains': set(),
            'suspicious_ips': set(),
            'malware_hashes': set(),
            'phishing_urls': set(),
            'c2_servers': set(),
            'malware_families': {},
            'iocs': []  # Indicators of Compromise
        }
        
        self.last_update = {}
        self.threat_scores = defaultdict(float)
        self.load_threat_data()


 
      
    def fetch_openphish_feed(self):
        """Fetch OpenPhish threat feed"""
        try:
            response = requests.get(self.sources['openphish'], timeout=30, 
                                  headers={'User-Agent': 'AdwareDetection/1.0'})
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                domains = set()
                for url in urls:
                    if url.startswith('http'):
                        try:
                            domain = urlparse(url).netloc.lower()
                            domains.add(domain)
                            self.threat_data['phishing_urls'].add(url)
                        except:
                            continue
                self.threat_data['malicious_domains'].update(domains)
                return len(domains)
        except Exception as e:
            logging.warning(f"Failed to fetch OpenPhish feed: {e}")
        return 0
    
    def fetch_malware_domains(self):
        """Fetch malware domains from multiple sources"""
        domains_count = 0
        try:
            response = requests.get(self.sources['malware_domains'], timeout=30)
            if response.status_code == 200:
                for line in response.text.strip().split('\n'):
                    if line and not line.startswith('#'):
                        domain = line.strip().lower()
                        if '.' in domain and not domain.startswith('.'):
                            self.threat_data['malicious_domains'].add(domain)
                            domains_count += 1
        except Exception as e:
            logging.warning(f"Failed to fetch malware domains: {e}")
        return domains_count
    
    def fetch_abuse_ch_data(self):
        """Fetch data from abuse.ch URLhaus"""
        try:
            response = requests.get(self.sources['abuse_ch'], timeout=30)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')[8:]  # Skip header
                for line in lines:
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 3:
                            url = parts[2].strip('"')
                            if url.startswith('http'):
                                try:
                                    domain = urlparse(url).netloc.lower()
                                    self.threat_data['malicious_domains'].add(domain)
                                    self.threat_data['phishing_urls'].add(url)
                                except:
                                    continue
                return True
        except Exception as e:
            logging.warning(f"Failed to fetch abuse.ch data: {e}")
        return False
    
    def analyze_domain_reputation(self, domain):
        """Analyze domain reputation using multiple factors"""
        score = 0.0
        factors = []
        
        # Check against known malicious domains
        if domain.lower() in self.threat_data['malicious_domains']:
            score += 10.0
            factors.append("Known malicious domain")
        
        # Domain age and registration analysis (simplified)
        if self._is_suspicious_domain_pattern(domain):
            score += 5.0
            factors.append("Suspicious domain pattern")
        
        # Length and character analysis
        if len(domain) > 50 or '-' in domain or any(char.isdigit() for char in domain):
            score += 2.0
            factors.append("Suspicious domain characteristics")
        
        # TLD analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.buzz', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 3.0
            factors.append("Suspicious TLD")
        
        return score, factors
    
    def _is_suspicious_domain_pattern(self, domain):
        """Check for suspicious domain patterns"""
        suspicious_patterns = [
            r'.*\d{4,}.*',  # Many digits
            r'.*-.*-.*',    # Multiple hyphens
            r'.*(ads?|popup|banner|click|money|cash|free|win|prize).*',
            r'.*\.(tk|ml|ga|cf)$'
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, domain.lower()):
                return True
        return False
    
    def update_all_sources(self):
        """Update threat intelligence from all sources"""
        total_updates = 0
        
        # OpenPhish
        count = self.fetch_openphish_feed()
        if count > 0:
            total_updates += count
            self.last_update['openphish'] = datetime.now()
        
        # Malware domains
        count = self.fetch_malware_domains()
        if count > 0:
            total_updates += count
            self.last_update['malware_domains'] = datetime.now()
        
        # Abuse.ch
        if self.fetch_abuse_ch_data():
            self.last_update['abuse_ch'] = datetime.now()
        
        # Update threat scores
        self._calculate_threat_scores()
        self.save_threat_data()
        
        logging.info(f"Threat intelligence updated: {total_updates} new indicators")
        return total_updates > 0
    
    def _calculate_threat_scores(self):
        """Calculate threat scores for all domains"""
        for domain in self.threat_data['malicious_domains']:
            score, _ = self.analyze_domain_reputation(domain)
            self.threat_scores[domain] = score
    
    def is_malicious(self, indicator, indicator_type='domain'):
        """Check if an indicator is malicious with confidence score"""
        if indicator_type == 'domain':
            score, factors = self.analyze_domain_reputation(indicator)
            return score > 5.0, score, factors
        elif indicator_type == 'ip':
            return indicator in self.threat_data['suspicious_ips'], 0.0, []
        elif indicator_type == 'hash':
            return indicator in self.threat_data['malware_hashes'], 0.0, []
        return False, 0.0, []
    def save_threat_data(self, filename="threat_data.pkl"):
        try:
            with open(filename, "wb") as f:
                pickle.dump(self.threat_data, f)
            logging.info(f"✅ Threat data saved to {filename}")
        except Exception as e:
            logging.error(f"❌ Failed to save threat data: {e}")

    def load_threat_data(self, filename="threat_data.pkl"):
        if os.path.exists(filename):
            try:
                with open(filename, "rb") as f:
                    self.threat_data = pickle.load(f)
                logging.info(f"✅ Threat data loaded from {filename}")
            except Exception as e:
                logging.error(f"❌ Failed to load threat data: {e}")