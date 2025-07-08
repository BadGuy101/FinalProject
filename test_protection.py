import unittest
from unittest.mock import patch, MagicMock
from core.security_manager import SecurityManager
from core.system_monitor import SystemMonitor
from core.exceptions import ProtectionError

class TestProcessProtection(unittest.TestCase):
    def setUp(self):
        self.sm = SecurityManager()
        self.sm.driver = MagicMock()
        self.sm.process_monitor = SystemMonitor()
        
        # Mock process validation
        self.sm.process_monitor.validate_pid = MagicMock(return_value=True)

    def test_protect_valid_process(self):
        """Test protecting a valid process"""
        self.sm.driver.protect_process.return_value = True
        result = self.sm.protect_process(1234)
        self.assertTrue(result)
        self.assertIn(1234, self.sm.protected_processes)

    def test_protect_invalid_process(self):
        """Test protecting invalid PID"""
        self.sm.process_monitor.validate_pid.return_value = False
        result = self.sm.protect_process(99999)
        self.assertFalse(result)
        self.assertNotIn(99999, self.sm.protected_processes)

    def test_protect_duplicate_process(self):
        """Test protecting already protected process"""
        self.sm.protected_processes.add(1234)
        result = self.sm.protect_process(1234)
        self.assertFalse(result)  # Should fail silently

    def test_driver_failure(self):
        """Test driver failure during protection"""
        self.sm.driver.protect_process.side_effect = DriverError("Test error")
        with self.assertRaises(ProtectionError):
            self.sm.protect_process(1234)

    def test_protection_list_sync(self):
        """Test protected process list remains synced"""
        self.sm.protect_process(1001)
        self.sm.protect_process(1002)
        self.assertEqual(len(self.sm.protected_processes), 2)
        
        # Simulate driver restart
        self.sm.protected_processes.clear()
        self.sm.load_protected_list()  # Would normally query driver
        self.assertEqual(len(self.sm.protected_processes), 0)  # Mock returns empty
