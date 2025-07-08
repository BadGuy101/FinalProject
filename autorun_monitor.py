# core/autorun_monitor.py

import os
import winreg
import logging
from pathlib import Path

SUSPICIOUS_KEYWORDS = ["ad", "popup", "banner", "speedup", "toolbar", "update", "driver"]

class AutorunMonitor:
    """Monitors Windows registry and startup folders for suspicious autorun entries."""

    def __init__(self):
        self.startup_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")

    def check_registry_run_keys(self):
        """Scan common autorun registry keys for suspicious values"""
        suspicious_entries = []

        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for root, subkey in locations:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(word in value.lower() for word in SUSPICIOUS_KEYWORDS):
                            suspicious_entries.append({
                                'source': f"{root}\\{subkey}",
                                'name': name,
                                'value': value
                            })
            except Exception as e:
                logging.debug(f"Registry check failed for {subkey}: {e}")
        return suspicious_entries

    def check_startup_folder(self):
        """Scan Windows startup folder for suspicious files"""
        suspicious_files = []

        try:
            for item in Path(self.startup_folder).glob("*"):
                if any(word in item.name.lower() for word in SUSPICIOUS_KEYWORDS):
                    suspicious_files.append(str(item))
        except Exception as e:
            logging.debug(f"Startup folder check failed: {e}")

        return suspicious_files

    def scan_autoruns(self):
        """Run full autorun scan and return issues"""
        return {
            "registry_hits": self.check_registry_run_keys(),
            "startup_hits": self.check_startup_folder()
        }
