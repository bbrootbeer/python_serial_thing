# serial_utils.py
import sys
import serial.tools.list_ports

from common import SOF, FRAME_SIZE

def choose_serial_port():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports found.")
        sys.exit(1)

    print("Available serial ports:")
    for i, port in enumerate(ports):
        print(f"{i}: {port.device} - {port.description}")

    choice = input("Select port number: ")
    try:
        index = int(choice)
        return ports[index].device
    except (ValueError, IndexError):
        print("Invalid choice.")
        sys.exit(1)

def find_frame_start(buf, parse_frame_exclude_sof):
    for i in range(len(buf)):
        if buf[i] == SOF and (i + FRAME_SIZE) <= len(buf):
            candidate = buf[i:i + FRAME_SIZE]
            valid, _ = parse_frame_exclude_sof(candidate)
            if valid:
                return i
    return -1
