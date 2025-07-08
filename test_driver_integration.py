import unittest
import ctypes
from unittest.mock import patch, MagicMock
from core.driver_comm import DriverInterface
from core.exceptions import DriverError

class TestDriverIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This runs once before all tests
        cls.driver = DriverInterface()
        
    def setUp(self):
        # This runs before each test
        self.driver.device_handle = MagicMock()  # Mock handle

    def test_connection_success(self):
        """Test successful driver connection"""
        with patch('ctypes.windll.kernel32.CreateFileW', return_value=123):
            self.assertTrue(self.driver.connect())
            self.assertEqual(self.driver.device_handle, 123)

    def test_connection_failure(self):
        """Test failed driver connection"""
        with patch('ctypes.windll.kernel32.CreateFileW', return_value=-1):
            with self.assertRaises(DriverError):
                self.driver.connect()

    def test_ping_command(self):
        """Test basic driver communication"""
        with patch('ctypes.windll.kernel32.DeviceIoControl', return_value=1):
            self.driver.ping()
            # Verify IOCTL was called with correct code
            self.driver.device_handle.assert_called()

    def test_invalid_ioctl(self):
        """Test error handling for failed IOCTL"""
        with patch('ctypes.windll.kernel32.DeviceIoControl', return_value=0):
            with self.assertRaises(DriverError):
                self.driver.protect_process(1234)

    def test_memory_read(self):
        """Test memory read operation structure"""
        mock_ioctl = MagicMock(return_value=1)
        with patch('ctypes.windll.kernel32.DeviceIoControl', mock_ioctl):
            self.driver.read_memory(1234, 0x400000, 100)
            
            # Verify the structure was properly constructed
            args, _ = mock_ioctl.call_args
            self.assertEqual(args[1], self.driver.IOCTL_READ_MEMORY)

