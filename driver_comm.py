import ctypes
import logging
from ctypes import wintypes

class DriverInterface:
    def __init__(self):
        self.device_handle = None
        self.symlink = r"\\.\AdvShld_68737644"  # Custom symbolic link
        self._initialize_ioctls()

    def _initialize_ioctls(self):
        # Device Type (custom, must match your driver's .h file)
        self.IOCTL_PING = self._ctl_code(0x800)
        self.IOCTL_READ_MEMORY = self._ctl_code(0x801, access=1)
        self.IOCTL_PROTECT_PROCESS = self._ctl_code(0x802)
        self.IOCTL_SCAN_MEMORY = self._ctl_code(0x803)
        # Add more as needed...

    def _ctl_code(self, function, method=0, access=0):
        device_type = 0x22
        return (device_type << 16) | (access << 14) | (function << 2) | method

    def connect(self):
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.device_handle = kernel32.CreateFileW(
            self.symlink,
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0,
            None,
            3,  # OPEN_EXISTING
            0x80,  # FILE_ATTRIBUTE_NORMAL
            None
        )
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
        if self.device_handle == INVALID_HANDLE_VALUE:
            raise DriverError("Driver connection failed", ctypes.get_last_error())
        if self.device_handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            logging.error(f"[DriverInterface] CreateFileW failed: {ctypes.FormatError(err)}")
            raise DriverError("Driver connection failed", err)

    def disconnect(self):
        if self.device_handle and self.device_handle != -1:
            ctypes.windll.kernel32.CloseHandle(self.device_handle)
            self.device_handle = None

    def protect_process(self, pid):
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("Invalid PID")
        
        class ProcessRequest(ctypes.Structure):
            _fields_ = [("PID", wintypes.ULONG)]

        req = ProcessRequest(pid)
        return self._send_ioctl(self.IOCTL_PROTECT_PROCESS, req)

    def scan_memory(self, pid, start, size, pattern):
        if not isinstance(pattern, (bytes, bytearray)):
            raise ValueError("Pattern must be bytes or bytearray")

        class ScanRequest(ctypes.Structure):
            _fields_ = [
                ("PID", wintypes.ULONG),
                ("StartAddress", wintypes.ULONG_PTR),
                ("Size", ctypes.c_size_t),
                ("PatternSize", wintypes.ULONG),
                ("Pattern", ctypes.c_ubyte * len(pattern))
            ]

        pattern_array = (ctypes.c_ubyte * len(pattern))(*pattern)
        req = ScanRequest(pid, start, size, len(pattern), pattern_array)
        return self._send_ioctl(self.IOCTL_SCAN_MEMORY, req, output_size=1024)

    def _send_ioctl(self, code, input_struct=None, output_size=0):
        if input_struct is None:
            in_buffer = None
            in_size = 0
        else:
            in_buffer = ctypes.byref(input_struct)
            in_size = ctypes.sizeof(input_struct)

        out_buffer = ctypes.create_string_buffer(output_size)
        bytes_returned = wintypes.DWORD()

        success = ctypes.windll.kernel32.DeviceIoControl(
            self.device_handle,
            code,
            in_buffer,
            in_size,
            out_buffer,
            output_size,
            ctypes.byref(bytes_returned),
            None
        )

        if not success:
            raise DriverError("IOCTL failed", ctypes.get_last_error())

        return out_buffer.raw[:bytes_returned.value]

    def send_ping(self):
        """
        Sends a ping to the driver to check if it's responsive.
        Returns a PingResponse(success=True) if successful, else success=False with error.
        """
        try:
            # Ping should be a minimal no-op IOCTL, no input/output needed
            self._send_ioctl(self.IOCTL_PING, input_struct=None, output_size=0)
            return PingResponse(True)
        except DriverError as e:
            logging.warning(f"[DriverInterface] Ping failed: {e}")
            return PingResponse(False, error=str(e))

class PingResponse:
    def __init__(self, ok: bool, error: str = ""):
        self._ok = ok
        self._error = error

    def is_ok(self):
        return self._ok

    def get_error(self):
        return self._error
class DriverError(Exception):
    def __init__(self, message, code=None):
        super().__init__(f"{message} (code: {code})")
        self.code = code
