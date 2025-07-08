# core/network_sniffer.py

import pyshark
import threading
import logging
import subprocess
import asyncio
from queue import Queue
from config.settings import SUSPICIOUS_DOMAINS
from config import settings
from core.security_monitor import AdvancedSecurityMonitor
from core.quarantine_manager import QuarantineManager


class NetworkSniffer:
    """Captures and analyzes network packets in real time."""

    def __init__(self, interface='default', packet_limit=100, log_path="network_alert.log", stop_event=None):
        self.stop_event = stop_event or threading.Event()
        self.log_path = log_path
        self.interface = interface
        self.packet_limit = packet_limit
        self.capture_thread = None
        self.running = False
        self.results = Queue()
        self.logger = logging.getLogger("NetworkSniffer")

    @staticmethod
    def get_network_interfaces():
        try:
            result = subprocess.run(['dumpcap', '-D'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                index, name = line.split('.', 1)
                interfaces.append(name.strip())
            return interfaces
        except Exception as e:
            logging.warning(f"[⚠️] Failed to get interfaces: {e}")
            return []

    def _packet_callback(self, pkt):
        try:
            domain = None
            if hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):
                domain = pkt.http.host.lower()
            elif hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                domain = pkt.dns.qry_name.lower()

            if domain:
                for bad_domain in SUSPICIOUS_DOMAINS:
                    if bad_domain in domain:
                        alert = f"[⚠️] Suspicious domain contacted: {domain}"
                        self._log_alert(alert)
        except Exception as e:
            self.logger.warning(f"[Sniffer Parse Error] {e}")

    def _log_alert(self, message):
        self.results.put(message)
        self.logger.warning(message)
        try:
            with open(self.log_path, "a", encoding='utf-8') as f:
                f.write(message + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to log file: {e}")

    def start_capture(self):
        if self.running:
            return

        def _run():
            asyncio.set_event_loop(asyncio.new_event_loop())  # Fix for event loop in thread
            self.running = True
            try:
                capture = pyshark.LiveCapture(interface=self.interface, tshark_path=settings.TSHARK_PATH)
                for pkt in capture.sniff_continuously(packet_count=self.packet_limit):
                    if self.stop_event.is_set() or not self.running:
                        break
                    self._packet_callback(pkt)
            except Exception as e:
                self.logger.error(f"Sniffer error: {e}", exc_info=True)
            finally:
                self.running = False

        self.capture_thread = threading.Thread(target=_run, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.running = False
        self.stop_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)

    def get_alerts(self) -> list:
        alerts = []
        while not self.results.empty():
            alerts.append(self.results.get())
        return alerts
