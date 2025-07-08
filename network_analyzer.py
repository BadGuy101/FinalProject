class NetworkAnalyzer:
    """Advanced network traffic analysis for adware detection"""
    
    def __init__(self):
        self.suspicious_domains = set()
        self.ad_networks = {
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'facebook.com/tr', 'amazon-adsystem.com', 'adsystem.amazon.com',
            'media.net', 'outbrain.com', 'taboola.com', 'addthis.com',
            'sharethis.com', 'quantserve.com', 'scorecardresearch.com'
        }
        
        self.connection_monitor = {}
        self.dns_cache = {}
        self.traffic_stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'ad_requests': 0,
            'data_transferred': 0
        }
    
    def analyze_network_connections(self, connections):
        """Analyze current network connections for suspicious activity"""
        suspicious_connections = []
        
        for conn in connections:
            try:
                suspicion_score = 0
                reasons = []
                
                if conn.get('raddr'):
                    remote_ip = conn['raddr'].get('ip') if isinstance(conn['raddr'], dict) else str(conn['raddr'])
                    remote_port = conn['raddr'].get('port') if isinstance(conn['raddr'], dict) else 0
                    
                    # Check against known ad networks
                    if self._is_ad_network(remote_ip):
                        suspicion_score += 5
                        reasons.append('Connection to known ad network')
                    
                    # Check for suspicious ports
                    if remote_port in [8080, 8888, 9999, 1337, 31337]:
                        suspicion_score += 3
                        reasons.append(f'Suspicious port: {remote_port}')
                    
                    # Check connection frequency
                    conn_key = f"{remote_ip}:{remote_port}"
                    if conn_key in self.connection_monitor:
                        self.connection_monitor[conn_key]['count'] += 1
                        if self.connection_monitor[conn_key]['count'] > 10:
                            suspicion_score += 2
                            reasons.append('High connection frequency')
                    else:
                        self.connection_monitor[conn_key] = {'count': 1, 'first_seen': time.time()}
                    
                    # Geolocation check (simplified)
                    if self._is_suspicious_geolocation(remote_ip):
                        suspicion_score += 2
                        reasons.append('Suspicious geolocation')
                
                if suspicion_score >= 5:
                    suspicious_connections.append({
                        'connection': conn,
                        'suspicion_score': suspicion_score,
                        'reasons': reasons,
                        'severity': 'high' if suspicion_score >= 8 else 'medium'
                    })
                    
            except Exception as e:
                logging.debug(f"Error analyzing connection: {e}")
        
        self.traffic_stats['total_connections'] = len(connections)
        self.traffic_stats['suspicious_connections'] = len(suspicious_connections)
        
        return suspicious_connections
    
    def _is_ad_network(self, ip_or_domain):
        """Check if IP/domain belongs to known ad networks"""
        # Simple domain check
        for ad_domain in self.ad_networks:
            if ad_domain in str(ip_or_domain).lower():
                return True
        return False
    
    def _is_suspicious_geolocation(self, ip):
        """Check if IP is from suspicious geolocation (simplified)"""
        # This is a simplified implementation
        # In a real system, you'd use a proper geolocation service
        try:
            # Basic check for private IP ranges
            octets = ip.split('.')
            if len(octets) == 4:
                first_octet = int(octets[0])
                second_octet = int(octets[1])
                
                # Skip private IPs
                if (first_octet == 10 or 
                    (first_octet == 172 and 16 <= second_octet <= 31) or
                    (first_octet == 192 and second_octet == 168)):
                    return False
                
                # Check for suspicious ranges (this is overly simplified)
                if first_octet in [1, 2, 5, 223, 224, 225]:
                    return True
                    
        except (ValueError, IndexError):
            pass
        
        return False
    
    def monitor_dns_requests(self, dns_requests):
        """Monitor DNS requests for suspicious patterns"""
        suspicious_dns = []
        
        for request in dns_requests:
            try:
                domain = request.get('domain', '').lower()
                
                # Check against known malicious domains
                if self._is_suspicious_domain(domain):
                    suspicious_dns.append({
                        'domain': domain,
                        'reason': 'Known suspicious domain',
                        'severity': 'high'
                    })
                
                # Check for DGA (Domain Generation Algorithm) patterns
                if self._is_dga_domain(domain):
                    suspicious_dns.append({
                        'domain': domain,
                        'reason': 'Possible DGA domain',
                        'severity': 'medium'
                    })
                
                # Check for ad-related domains
                if self._is_ad_domain(domain):
                    suspicious_dns.append({
                        'domain': domain,
                        'reason': 'Advertisement domain',
                        'severity': 'low'
                    })
                    self.traffic_stats['ad_requests'] += 1
                    
            except Exception as e:
                logging.debug(f"Error analyzing DNS request: {e}")
        
        return suspicious_dns
    
    def _is_suspicious_domain(self, domain):
        """Check if domain is suspicious"""
        suspicious_patterns = [
            'ads', 'popup', 'banner', 'click', 'doubleclick',
            'adsystem', 'adnxs', 'adsrv', 'adform', 'adtech'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in domain:
                return True
        return False
    
    def _is_dga_domain(self, domain):
        """Check for Domain Generation Algorithm patterns"""
        if not domain or '.' not in domain:
            return False
        
        # Simple DGA detection heuristics
        domain_part = domain.split('.')[0]
        
        # Check for random-looking patterns
        if len(domain_part) > 15:  # Very long domain names
            return True
        
        # Check for high entropy (lots of random characters)
        if len(set(domain_part)) > len(domain_part) * 0.7:  # High character diversity
            return True
        
        # Check for patterns like alternating consonants/vowels
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        pattern_score = 0
        
        for i, char in enumerate(domain_part.lower()):
            if i > 0:
                prev_char = domain_part[i-1].lower()
                if ((char in vowels and prev_char in consonants) or
                    (char in consonants and prev_char in vowels)):
                    pattern_score += 1
        
        if pattern_score > len(domain_part) * 0.6:
            return True
        
        return False
    
    def _is_ad_domain(self, domain):
        """Check if domain is related to advertising"""
        ad_keywords = [
            'ads', 'ad', 'advertisement', 'banner', 'popup',
            'analytics', 'tracking', 'metrics', 'doubleclick',
            'googlesyndication', 'googleadservices'
        ]
        
        for keyword in ad_keywords:
            if keyword in domain:
                return True
        return False
