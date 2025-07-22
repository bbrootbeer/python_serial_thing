#!/usr/bin/env python3

import time
import sys
import serial
import argparse
import os
import struct

# --- IMPORT THE CRC16 LOOKUP TABLE ---
from crc16_ccitt_table import crc16_table # This line imports the table from your file

# --- extcap Constants ---
# These are standard DLT (Data Link Type) values for Wireshark
DLT_SOCKETCAN = 227 # Standard Linux SocketCAN DLT
EXTCAP_VERSION = "1.0"

# --- Your Custom Protocol Constants ---
SOF_FLOAT = 0xAA                # First Start-of-Frame byte (floating preamble)
SOF_WRAPPED = 0x69              # Second Start-of-Frame byte (wrapped, part of CRC)

# --- START MODIFICATIONS HERE ---
# Correct length for the standard Linux 'struct can_frame' that Wireshark DLT_SOCKETCAN expects
# This includes 4 bytes for CAN ID, 1 byte for DLC, 3 bytes for padding, 8 bytes for data
WIRESHARK_SOCKETCAN_FRAME_LEN = 16

# This remains 13, as it's the size of the *actual* CAN content within your serial protocol
# (ID, DLC, 8 data bytes)
# Let's rename it for clarity to distinguish from Wireshark's expected frame size
CUSTOM_CAN_CONTENT_LEN = 13

CRC_LEN = 2                     # Length of the CRC-16
# end modifications here
CRC_LEN = 2 # Length of the CRC-16


# Use CUSTOM_CAN_CONTENT_LEN for your protocol's CRC calculation and total packet length
PACKET_LEN_CRC_COVERED = 1 + CUSTOM_CAN_CONTENT_LEN # Length of data covered by CRC (0x69 + custom CAN content) = 1 + 13 = 14 bytes
PACKET_LEN_TOTAL = 1 + PACKET_LEN_CRC_COVERED + CRC_LEN # Total custom packet length (0xAA + 14 bytes + 2 bytes CRC) = 1 + 14 + 2 = 17 bytes
# --- END MODIFICATIONS HERE ---

# --- CRC-16 CCITT Parameters (matching your Teensy code) ---
# CRC16_POLY = 0x1021 # No longer directly used in the table-driven function, but good to keep for reference
CRC16_INIT = 0xFFFF

# --- MODIFIED CRC-16 FUNCTION TO USE THE TABLE ---
def crc16_ccitt_lookup(data_bytes: bytes, initial_value: int = CRC16_INIT) -> int:
    """
    Calculates CRC-16 CCITT using the pre-computed lookup table,
    matching the logic of your Teensy code.
    """
    crc = initial_value
    for byte_val in data_bytes:
        # byte_val is an integer (0-255) when iterating over bytes
        tbl_idx = ((crc >> 8) ^ byte_val) & 0xFF # high byte XOR input, ensure it's 8-bit index
        crc = (crc << 8) ^ crc16_table[tbl_idx]
        crc &= 0xFFFF # Ensure CRC stays 16-bit
    return crc


def print_extcap_interfaces():
    """Prints the extcap interfaces list."""
    print(f"extcap {{version={EXTCAP_VERSION}}}{os.linesep}", file=sys.stdout)
    print(f"interface {{value=wowcan}}{{display=wowcan2shark}}{{help=Capture CAN data from Teensy via custom serial protocol}}{os.linesep}", file=sys.stdout)
    sys.stdout.flush()

def print_extcap_dlt():
    """Prints the DLTs supported by the interface."""
    print(f"dlt {{value={DLT_SOCKETCAN}}}{{display=Linux SocketCAN (CAN Bus)}}{{linktype=CAN_2_0}}{os.linesep}", file=sys.stdout)
    sys.stdout.flush()

def print_extcap_config():
    """Prints the extcap configuration options."""
    # arg {number} must be unique for each argument
    # call={--arg-name} must match your argparse argument names
    # display is what user sees in Wireshark GUI
    # type=string|integer|boolean|enum
    # required=true|false
    # default (optional)
    # tooltip (optional)

    print(f"arg {{number=0}}{{call=--serial-port}}{{display=Serial Port}}{{type=string}}{{required=true}}{{tooltip=The serial port (e.g., COM4 or /dev/ttyACM0)}}", file=sys.stdout)
    print(f"arg {{number=1}}{{call=--baudrate}}{{display=Baud Rate}}{{type=integer}}{{required=true}}{{default=115200}}{{tooltip=The serial baud rate (default: 115200)}}", file=sys.stdout)
    sys.stdout.flush()

def capture_loop(serial_port, fifo_path, baudrate):
    """
    Main capture loop: reads from serial, parses custom frames, and writes
    SocketCAN frames to the FIFO, prepended with a pcap global header
    and per-packet pcap headers.
    """
    try:
        ser = serial.Serial(serial_port, baudrate, timeout=0.1)
        # For binary output, direct to buffer
        if fifo_path:
            fifo = open(fifo_path, 'wb')
        else:
            # Fallback for direct piping (might not be used by Wireshark)
            fifo = sys.stdout.buffer

        sys.stderr.write(f"extcap: Starting capture on {serial_port} at {baudrate} baud.\n")
        sys.stderr.write(f"extcap: Writing to FIFO: {fifo_path or 'stdout'}\n")
        sys.stderr.flush()

        # --- 1. WRITE PCAP GLOBAL HEADER (ONCE) ---
        # https://wiki.wireshark.org/Development/LibpcapFileFormat
        # Magic Number (0xA1B2C3D4 for little-endian, 0xD4C3B2A1 for big-endian)
        # Version (2.4 recommended)
        # Time Zone Offset (0)
        # Sigfigs (0)
        # Snaplen (max packet length, 0xFFFF means no limit for 16-bit, or a large number for 32-bit)
        # Link-layer type (DLT) - DLT_SOCKETCAN (227)

        # Using '<' for little-endian byte order
        pcap_global_header = struct.pack(
            '<IHIIIIH',
            0xA1B2C3D4,  # magic_number (little-endian)
            0x0002,      # version_major (2)
            0x0004,      # version_minor (4)
            0,           # tz_offset (GMT, in seconds)
            0,           # sigfigs (accuracy of timestamps, usually 0)
            65535,       # snaplen (max bytes per packet, 65535 is common, or large enough for CAN)
            DLT_SOCKETCAN# linktype (227 for Linux SocketCAN)
        )
        
        fifo.write(pcap_global_header)
        fifo.flush() # IMPORTANT: Ensure header is written immediately
        sys.stderr.write(f"extcap: Wrote pcap global header: {pcap_global_header.hex()}\n")
        sys.stderr.flush()
        # --- END PCAP GLOBAL HEADER ---

        # Partial packet buffer
        partial_packet = b''
        
        while True: # Try to find and process a full packet
            # Read all available bytes
            try:
                bytes_to_read = ser.in_waiting or 1
                data = ser.read(bytes_to_read)
                if data:
                    pass
            except Exception as e:
                sys.stderr.write(f"extcap: Serial read error: {e}\n")
                sys.stderr.flush()
                time.sleep(0.01)
                continue

            if not data:
                continue

            partial_packet += data

            while True: # Try to find and process a full packet from the buffer
                # Stage 1: Find SOF_FLOAT (0xAA)
                sof_float_idx = partial_packet.find(SOF_FLOAT.to_bytes(1, 'little'))
                if sof_float_idx == -1:
                    # No SOF_FLOAT found, clear buffer if it's too long to prevent overflow
                    if len(partial_packet) > PACKET_LEN_TOTAL * 2: # Keep some window
                        partial_packet = partial_packet[-PACKET_LEN_TOTAL:]
                    break # Wait for more data

                # Discard data before SOF_FLOAT
                if sof_float_idx > 0:
                    sys.stderr.write(f"extcap: Discarding {sof_float_idx} bytes before SOF_FLOAT.\n")
                    sys.stderr.flush()
                    partial_packet = partial_packet[sof_float_idx:]
                    sof_float_idx = 0 # Now SOF_FLOAT is at index 0

                # Stage 2: Check if enough bytes for a full packet
                if len(partial_packet) < PACKET_LEN_TOTAL:
                    break # Not enough data for a full packet, wait for more

                # We have a potential full packet (17 bytes) starting with SOF_FLOAT
                current_packet_candidate = partial_packet[:PACKET_LEN_TOTAL]

                # Stage 3: Validate SOF_WRAPPED (0x69)
                if current_packet_candidate[1] != SOF_WRAPPED:
                    sys.stderr.write(f"extcap: Mismatch on SOF_WRAPPED. Expected {SOF_WRAPPED:02X}, got {current_packet_candidate[1]:02X}. Discarding packet.\n")
                    sys.stderr.flush()
                    partial_packet = partial_packet[1:] # Discard SOF_FLOAT and re-scan from next byte
                    continue # Try again with the truncated buffer

                # Stage 4: Validate CRC
                # CRC is calculated over bytes from SOF_WRAPPED (index 1) to end of data (index 14)
                data_for_crc = current_packet_candidate[1 : 1 + PACKET_LEN_CRC_COVERED]
                received_crc_bytes = current_packet_candidate[1 + PACKET_LEN_CRC_COVERED : PACKET_LEN_TOTAL]
                
                # Reconstruct received CRC (big-endian because Teensy sends MSB then LSB)
                received_crc = (received_crc_bytes[0] << 8) | received_crc_bytes[1]
                
                # --- CALL THE NEW CRC LOOKUP FUNCTION ---
                calculated_crc = crc16_ccitt_lookup(data_for_crc)

                if received_crc != calculated_crc:
                    sys.stderr.write(f"extcap: CRC mismatch! Calculated {calculated_crc:04X}, Received {received_crc:04X}. Discarding packet.\n")
                    sys.stderr.flush()
                    partial_packet = partial_packet[1:] # Discard SOF_FLOAT and re-scan
                    continue # Try again with the truncated buffer

                # If we reach here, the packet is valid!
                sys.stderr.write(f"extcap: Valid packet received. Raw: {current_packet_candidate.hex().upper()}\n")
                sys.stderr.flush()

                # --- START CORE MODIFICATIONS FOR SOCKETCAN FRAME CREATION ---
                # Extract the components of the CAN message from your custom 17-byte serial packet.
                # Custom Packet Format: 0xAA | 0x69 | CAN_ID(4) | DLC(1) | CAN_DATA(8) | CRC(2)
                # Indices: 0       1        2-5         6         7-14          15-16
                can_id_bytes = current_packet_candidate[2:6]
                dlc_byte = current_packet_candidate[6] # This is already an integer byte
                can_data_bytes = current_packet_candidate[7:15]

                # Convert the raw CAN ID bytes to an integer for struct.pack
                can_id_int = struct.unpack('<I', can_id_bytes)[0]
                
                # Construct the 16-byte standard Linux 'struct can_frame' payload
                # Format: '<IB3x8s'
                #   '<' : little-endian byte order
                #   'I' : unsigned int (4 bytes) for can_id
                #   'B' : unsigned char (1 byte) for can_dlc
                #   '3x': 3 pad bytes (Wireshark expects this for DLT_SOCKETCAN)
                #   '8s': 8-byte string/bytes for data[8]
                socketcan_frame_payload = struct.pack(
                    '<IB3x8s',
                    can_id_int,         # The 4-byte CAN ID as an integer
                    dlc_byte,           # The 1-byte DLC as an integer
                    can_data_bytes      # The 8-byte CAN data as a bytes object
                )

                sys.stderr.write(f"extcap: Prepared {len(socketcan_frame_payload)}-byte SocketCAN payload: {socketcan_frame_payload.hex().upper()}\n")
                sys.stderr.flush()
                # --- END CORE MODIFICATIONS ---

                # --- 2. WRITE PCAP PACKET HEADER (FOR EACH PACKET) ---
                current_time = time.time()
                ts_sec = int(current_time)
                ts_usec = int((current_time - ts_sec) * 1_000_000) # Convert fraction to microseconds

                pcap_packet_header = struct.pack(
                    '<IIII',
                    ts_sec,             # Timestamp seconds
                    ts_usec,            # Timestamp microseconds
                    WIRESHARK_SOCKETCAN_FRAME_LEN, # Captured packet length (must be 16)
                    WIRESHARK_SOCKETCAN_FRAME_LEN  # Original packet length (must be 16)
                )
                fifo.write(pcap_packet_header)
                # --- END PCAP PACKET HEADER ---

                # --- Write the 16-byte SocketCAN payload to the FIFO ---
                fifo.write(socketcan_frame_payload) # Write the correctly structured 16-byte payload
                fifo.flush() # Ensure data is written immediately

                # Remove the processed packet from the buffer
                partial_packet = partial_packet[PACKET_LEN_TOTAL:]

    except serial.SerialException as e:
        sys.stderr.write(f"extcap: Error opening serial port: {e}\n")
        sys.stderr.flush()
        sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("extcap: Capture interrupted.\n")
        sys.stderr.flush()
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()
        if 'fifo' in locals() and fifo != sys.stdout.buffer:
            fifo.close()
        sys.stderr.write("extcap: Capture finished.\n")
        sys.stderr.flush()


def main():
    parser = argparse.ArgumentParser(description="Teensy CAN over Serial extcap interface for Wireshark")
    parser.add_argument("--extcap-interfaces", action="store_true", help="List available interfaces")
    parser.add_argument("--extcap-dlts", action="store_true", help="List DLTs for a given interface")
    parser.add_argument("--extcap-interface", help="Specify the interface to capture on (e.g., teensy_can)")
    parser.add_argument("--extcap-capture-filter", help="Not supported by this extcap")
    parser.add_argument("--extcap-control-in", help="Not supported by this extcap")
    parser.add_argument("--extcap-control-out", help="Not supported by this extcap")
    parser.add_argument("--extcap-version", action="store_true", help="Print extcap version")
    parser.add_argument("--capture", action="store_true", help="Start capturing")
    parser.add_argument("--fifo", help="Named pipe (FIFO) to write captured data to")

    # --- ADD THIS LINE FOR --extcap-config ---
    parser.add_argument("--extcap-config", action="store_true", help="List configuration options for a given interface")
    # --- END ADDITION ---
    
    # Custom arguments for our specific extcap
    parser.add_argument("--serial-port", required=False, help="Serial port to connect to (e.g., COM4 or /dev/ttyACM0)")
    parser.add_argument("--baudrate", type=int, default=115200, help="Serial baud rate (default: 115200)")

    args = parser.parse_args()

    if args.extcap_interfaces:
        print_extcap_interfaces()
    elif args.extcap_dlts:
        # When Wireshark calls --extcap-dlts, it also provides --extcap-interface
        if not args.extcap_interface or args.extcap_interface != "wowcan": # Ensure it's for our interface
            sys.stderr.write("extcap: --extcap-dlts requires --extcap-interface and must be 'wowcan'\n")
            sys.stderr.flush()
            sys.exit(1)
        print_extcap_dlt()
    # --- ADD THIS NEW BLOCK ---
    elif args.extcap_config:
        # When Wireshark calls --extcap-config, it also provides --extcap-interface
        if not args.extcap_interface or args.extcap_interface != "wowcan": # Ensure it's for our interface
            sys.stderr.write("extcap: --extcap-config requires --extcap-interface and must be 'wowcan'\n")
            sys.stderr.flush()
            sys.exit(1)
        print_extcap_config()
    # --- END NEW BLOCK ---
    elif args.extcap_version:
        print(EXTCAP_VERSION)
        sys.stdout.flush()
    elif args.capture:
        if not args.serial_port:
            sys.stderr.write("extcap: --serial-port is required for capture.\n")
            sys.stderr.flush()
            sys.exit(1)
        capture_loop(args.serial_port, args.fifo, args.baudrate)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()