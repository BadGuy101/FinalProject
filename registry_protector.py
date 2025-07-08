# core/registry_protector.py

import winreg
import logging
import win32api
import win32con

WATCHED_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Classes\ms-settings\shell\open\command"),  # UAC Bypass
]

SUSPICIOUS_KEYWORDS = ["cmd", "powershell", "regsvr", "vbs", "hta", "wscript", "dropper", "schtasks", "shell"]

class RegistryProtector:
    def __init__(self):
        self.threats_found = []

    def scan_registry(self):
        """Scan startup-related registry keys for suspicious values."""
        self.threats_found.clear()

        for hive, subkey in WATCHED_KEYS:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(keyword in value.lower() for keyword in SUSPICIOUS_KEYWORDS):
                            full_path = f"{subkey}\\{name}"
                            self.threats_found.append((full_path, value))
                            logging.warning(f"[RegistryProtector] Suspicious autorun entry: {full_path} = {value}")
            except FileNotFoundError:
                continue
            except Exception as e:
                logging.error(f"[RegistryProtector] Failed to read {subkey}: {e}")

        return self.threats_found

    def delete_suspicious_entries(self):
        """Delete all suspicious registry values found during scan."""
        for hive, subkey in WATCHED_KEYS:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    for path, value in self.threats_found:
                        name = path.split("\\")[-1]
                        try:
                            winreg.DeleteValue(key, name)
                            logging.info(f"[RegistryProtector] Deleted suspicious entry: {path}")
                        except Exception as e:
                            logging.error(f"[RegistryProtector] Could not delete {path}: {e}")
            except Exception:
                continue
