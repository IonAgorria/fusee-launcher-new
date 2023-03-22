from rcm_backend import RCMHax

import usb

# Standard Nvidia USB VendorID.
NVIDIA_VID = 0x0955

# USB productID's for various Tegra devices.
T20_PIDS  = [0x7820]
T30_PIDS  = [0x7030, 0x7130, 0x7330]
T114_PIDS = [0x7335, 0x7535]
T124_PIDS = [0x7140, 0x7f40]
T132_PIDS = [0x7F13]
T210_PIDS = [0x7321, 0x7721]

# RCM Protocol header sizes.
RCM_V1_HEADER_SIZE = 116
RCM_V35_HEADER_SIZE = 628
RCM_V40_HEADER_SIZE = 644
RCM_V4P_HEADER_SIZE = 680

def detect_device(wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False) -> RCMHax:
    while True:
        if pid is None:
            devs = usb.core.find(find_all=1, idVendor=NVIDIA_VID)
        else:
            devs = usb.core.find(find_all=1, idVendor=NVIDIA_VID, idProduct=pid)

        for dev in devs:
            try:
                if dev.idProduct in T20_PIDS:
                    return T20(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                elif dev.idProduct in T30_PIDS:
                    return T30(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                elif dev.idProduct in T114_PIDS:
                    return T114(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                elif dev.idProduct in T124_PIDS:
                    return T124(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                elif dev.idProduct in T132_PIDS:
                    return T132(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                elif dev.idProduct in T210_PIDS:
                    return T210(vid=dev.idVendor, pid=dev.idProduct, wait_for_device=wait_for_device, os_override=os_override, override_checks=override_checks, debug=debug)
                else:
                    print("detected an unknown Nvidia device")
                    print("If this is an error please add the ProductID to SoC.py")
            except IOError as e:
                print(e)
                sys.exit(-1)
        if not wait_for_device:
            break

    return None

class T20(RCMHax):
    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40008000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # 512 Byte should be enough? #0x40009E40

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)

class T30(RCMHax):
    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V1_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000A000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40005000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.RCM_PAYLOAD_ADDR - 420 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)

class T114(RCMHax):
    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V35_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END - 1572 # exact position is known.
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 4

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)

class T124(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000E000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)

class T132(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V40_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x4000F000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40008000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)

class T210(RCMHax):

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False, debug=False):
        self.RCM_HEADER_SIZE  = RCM_V4P_HEADER_SIZE
        self.RCM_PAYLOAD_ADDR = 0x40010000

        self.COPY_BUFFER_ADDRESSES   = [0, 0x40009000] # Lower Buffer doesn't matter

        self.STACK_END           = self.RCM_PAYLOAD_ADDR  
        self.STACK_SPRAY_END     = self.STACK_END
        self.STACK_SPRAY_START   = self.STACK_SPRAY_END - 0x200 # Might not be enough

        RCMHax.__init__(self, wait_for_device=wait_for_device, os_override=os_override, vid=vid, pid=pid, override_checks=override_checks, debug=debug)
