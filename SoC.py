from rcm_backend import EPHax, RCMHax, IRAMHax

import usb

# Standard Nvidia USB VendorID.
NVIDIA_VID = 0x0955

# USB productID's for various Tegra devices.
T20_PIDS  = [0x7820, 0x7F20]
T30_PIDS  = [0x7030, 0x7130, 0x7330]
T114_PIDS = [0x7335, 0x7535]
T124_PIDS = [0x7140, 0x7740, 0x7f40]
T132_PIDS = [0x7F13]
T210_PIDS = [0x7321, 0x7721]

# RCM Protocol header sizes.
RCM_V1_HEADER_SIZE = 116
RCM_V35_HEADER_SIZE = 628
RCM_V40_HEADER_SIZE = 644
RCM_V4P_HEADER_SIZE = 680

def select_device_hax(arguments, vid, pid) -> EPHax|None:
    try:
        if pid in T20_PIDS:
            return T20(arguments=arguments, vid=vid, pid=pid)
        elif pid in T30_PIDS:
            return T30(arguments=arguments, vid=vid, pid=pid)
        elif pid in T114_PIDS:
            return T114(arguments=arguments, vid=vid, pid=pid)
        elif pid in T124_PIDS:
            return T124(arguments=arguments, vid=vid, pid=pid)
        elif pid in T132_PIDS:
            return T132(arguments=arguments, vid=vid, pid=pid)
        elif pid in T210_PIDS:
            return T210(arguments=arguments, vid=vid, pid=pid)
        else:
            print(f"Detected an unknown Nvidia device! VID {vid:04x} PID {pid:04x}")
            print("If this is an error please add the ProductID to SoC.py")
            return None
    except IOError as e:
        print(e)
        exit(-1)

def detect_device(arguments) -> EPHax|None:
    if arguments.vid is None:
        arguments.vid = NVIDIA_VID

    if arguments.force_soc:
        if arguments.pid is None:
            print("No SoC's USB Product ID was specified!")
            exit(1)
        return select_device_hax(arguments, vid=arguments.vid, pid=arguments.pid)

    while True:
        if arguments.pid is None:
            devs = usb.core.find(find_all=1, idVendor=arguments.vid)
        else:
            devs = usb.core.find(find_all=1, idVendor=arguments.vid, idProduct=arguments.pid)

        for dev in devs:
            result = select_device_hax(arguments, vid=dev.idVendor, pid=dev.idProduct)
            if result is not None:
                return result

        if not arguments.wait_for_device:
            break

    return None

class T20(IRAMHax):
    def __init__(self, *args, **kwargs):
        self.IRAM_PAYLOAD_ADDR = 0x40008000
        self.IRAM_EP0_BUFFER_ADDRESS = 0x40003000
        
        self.STACK_END         = 0x40008000
        self.STACK_SPRAY_START = 0x4000222C #This will fall to the return address in stack
        self.STACK_SPRAY_END   = self.STACK_SPRAY_START + 4

        IRAMHax.__init__(self, *args, **kwargs)

class T30(RCMHax):
    def __init__(self, *args, **kwargs):
        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000A000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END - 420 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4

        RCMHax.__init__(self, *args, **kwargs)

class T114(RCMHax):
    def __init__(self, *args, **kwargs):
        self.RCM_HEADER_SIZE  = RCM_V35_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END - 1572 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4

        RCMHax.__init__(self, *args, **kwargs)

class T124(RCMHax):

    def __init__(self, *args, **kwargs):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END - 0x280
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x638

        RCMHax.__init__(self, *args, **kwargs)

class T132(RCMHax):

    def __init__(self, *args, **kwargs):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000F000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        RCMHax.__init__(self, *args, **kwargs)

class T210(RCMHax):

    def __init__(self, *args, **kwargs):
        self.RCM_HEADER_SIZE  = RCM_V4P_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40010000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40009000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        RCMHax.__init__(self, *args, **kwargs)
