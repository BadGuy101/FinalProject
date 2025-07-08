# utils/helpers.py

import math
import re
import socket

def calculate_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy of the given byte string.
    """
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def is_valid_ip(ip: str) -> bool:
    """
    Validates an IPv4 address.
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
def validate_pid(self, pid):
    """Check if PID exists and is valid"""
    try:
        return psutil.pid_exists(pid) and pid > 8
    except:
        return False
            
def get_memory_regions(self, pid):
    """Get executable memory regions for scanning"""
    # This would use Pymem or similar in real implementation
    return [(0x400000, 0x1000)]  # Example region
        
def get_running_processes(self):
    """Get list of processes with protection status"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append({
            'pid': proc.pid,
            'name': proc.name(),
            'protected': proc.pid in self.protected_processes
        })
    return processes