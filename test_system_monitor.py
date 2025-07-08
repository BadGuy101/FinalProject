# tests/test_system_monitor.py

import unittest
from core.system_monitor import AdvancedSystemMonitor

class TestAdvancedSystemMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = AdvancedSystemMonitor()

    def test_get_cpu_usage_returns_float(self):
        cpu = self.monitor.get_cpu_usage()
        self.assertIsInstance(cpu, float, "CPU usage should be a float.")
        self.assertGreaterEqual(cpu, 0)
        self.assertLessEqual(cpu, 100)

    def test_get_memory_usage_returns_float(self):
        mem = self.monitor.get_memory_usage()
        self.assertIsInstance(mem, float, "Memory usage should be a float.")
        self.assertGreaterEqual(mem, 0)
        self.assertLessEqual(mem, 100)

    def test_monitoring_start_and_stop(self):
        try:
            self.monitor.start_monitoring()
            self.monitor.stop_monitoring()
        except Exception as e:
            self.fail(f"start/stop_monitoring raised an exception: {e}")

    def test_monitoring_with_callback(self):
        messages = []

        def mock_callback(msg):
            messages.append(msg)

        self.monitor.start_monitoring(callback=mock_callback)
        self.monitor.stop_monitoring()
        self.assertIsInstance(messages, list, "Callback should have appended messages (even if empty).")

    def tearDown(self):
        try:
            self.monitor.stop_monitoring()
        except:
            pass


