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
from time import sleep

import usb

from SoC import *


current_dir = os.path.dirname(os.path.abspath(__file__))

def parse_usb_id(id):
    """ Quick function to parse VID/PID arguments. """
    return int(id, 16)

# Read our arguments.
parser = argparse.ArgumentParser(description='launcher for the fusee gelee exploit (by @ktemkin)')
parser.add_argument('payload', metavar='payload', type=str, help='ARM payload to be launched')
parser.add_argument('-w', dest='wait_for_device', action='store_true', help='wait for an RCM connection if one isn\'t present')
parser.add_argument('-V', '--vid', metavar='vendor_id', dest='vid', type=parse_usb_id, default=None, help='overrides the TegraRCM vendor ID')
parser.add_argument('-P', '--pid', metavar='product_id', dest='pid', type=parse_usb_id, default=None, help='overrides the TegraRCM product ID')
parser.add_argument('--override-os', metavar='platform', dest='platform', type=str, default=None, help='overrides the detected OS; for advanced users only')
parser.add_argument('--relocator', metavar='binary', dest='relocator', type=str, default=None, help='provides the path to the intermezzo relocation stub')
parser.add_argument('--override-checks', dest='skip_checks', action='store_true', help="don't check for a supported controller; useful if you've patched your EHCI driver")
parser.add_argument('--allow-failed-id', dest='permissive_id', action='store_true', help="continue even if reading the device's ID fails; useful for development but not for end users")
parser.add_argument('--tty', dest='tty_mode', action='store_true', help="dump usb transfers to stdout")
parser.add_argument('-o', metavar='output_file', dest='output_file', type=str, help='dump usb transfers to file')
parser.add_argument('--debug', dest='debug', action='store_true', help="enable additional debug output")
parser.add_argument('--force-soc', dest='force_soc', action='store_true', help="force a specific soc")
parser.add_argument('--override-usb-path', dest='override_usb_path', type=str, default=None, help='override usb paath')
parser.add_argument('--skip-upload', dest='skip_upload', action='store_true', help="don't send payload")
parser.add_argument('--skip-smash', dest='skip_smash', action='store_true', help="don't trigger stack smashing")

arguments = parser.parse_args()
arguments.current_dir = current_dir

# Automatically choose the correct SoC based on the USB product ID.
rcm_device = detect_device(arguments)
if rcm_device is None:
    print("No RCM device found")
    sys.exit(-1)
else:
    print("Detected a" , type(rcm_device).__name__, "SoC")
    print('VendorID=' + hex(rcm_device.vid) + ' & ProductID=' + hex(rcm_device.pid))

if arguments.skip_upload:
    print("Skipping uploading payload")
else:
    rcm_device.upload_payload(arguments)

if arguments.skip_smash:
    if arguments.debug:
        print("Skipping the stack smashing")
    exit(0)

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    rcm_device.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

rcm_device.post_trigger()

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
