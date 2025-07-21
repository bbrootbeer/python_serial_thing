#!/usr/bin/env python3

import sys
import serial
import argparse
import os
import struct # For packing/unpacking if needed, though not strictly required for this fixed layout

# --- IMPORT THE CRC16 LOOKUP TABLE ---
from crc16_ccitt_table import crc16_table # This line imports the table from your file

# --- extcap Constants ---
# These are standard DLT (Data Link Type) values for Wireshark
DLT_SOCKETCAN = 227 # Standard Linux SocketCAN DLT
EXTCAP_VERSION = "1.0"

# --- Your Custom Protocol Constants ---
SOF_FLOAT = 0xAA                # First Start-of-Frame byte (floating preamble)
SOF_WRAPPED = 0x69              # Second Start-of-Frame byte (wrapped, part of CRC)
SOCKETCAN_FRAME_LEN = 13        # Length of the actual SocketCAN frame
CRC_LEN = 2                     # Length of the CRC-16
PACKET_LEN_CRC_COVERED = 1 + SOCKETCAN_FRAME_LEN # Length of data covered by CRC (0x69 + SocketCAN frame) = 1 + 13 = 14 bytes
PACKET_LEN_TOTAL = 1 + PACKET_LEN_CRC_COVERED + CRC_LEN # Total custom packet length (0xAA + 14 bytes + 2 bytes CRC) = 1 + 14 + 2 = 17 bytes

# --- CRC-16 CCITT Parameters (matching your Teensy code) ---
CRC16_POLY = 0x1021
CRC16_INIT = 0xFFFF

CRC16_POLY = 0x1021
def crc16_ccitt_table(data_bytes: bytes, initial_value: int = CRC16_INIT) -> int:
    """
    Calculates CRC-16 CCITT (polynomial 0x1021, initial 0xFFFF, no reflection, no final XOR)
    using a pre-computed lookup table (which is what your Teensy code does effectively).
    This Python implementation will calculate it bit-by-bit for simplicity,
    but the result should match your Teensy's table-driven approach.
    """
    crc = initial_value
    for byte in data_bytes:
        crc ^= (byte << 8)  # XOR with current byte, shifted to MSB of CRC
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ CRC16_POLY
            else:
                crc <<= 1
        crc &= 0xFFFF # Ensure CRC stays 16-bit
    return crc


def print_extcap_interfaces():
    """Prints the extcap interfaces list."""
    print(f"extcap {{version={EXTCAP_VERSION}}}{os.linesep}", file=sys.stdout)
    print(f"interface {{value=teensy_can}}{{display=Teensy CAN over Serial}}{{help=Capture CAN data from Teensy via custom serial protocol}}{os.linesep}", file=sys.stdout)
    sys.stdout.flush()

def print_extcap_dlt():
    """Prints the DLTs supported by the interface."""
    print(f"dlt {{value={DLT_SOCKETCAN}}}{{display=Linux SocketCAN (CAN Bus)}}{{linktype=CAN_2_0}}{os.linesep}", file=sys.stdout)
    sys.stdout.flush()

def capture_loop(serial_port, fifo_path, baudrate):
    """
    Main capture loop: reads from serial, parses custom frames, and writes
    SocketCAN frames to the FIFO.
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

        # Partial packet buffer
        partial_packet = b''
        
        while True:
            # Read all available bytes
            try:
                data = ser.read(ser.in_waiting or 1) # Read at least 1 byte if available, or all
            except Exception as e:
                sys.stderr.write(f"extcap: Serial read error: {e}\n")
                sys.stderr.flush()
                continue

            if not data:
                continue

            partial_packet += data

            while True: # Try to find and process a full packet
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
                
                calculated_crc = crc16_ccitt_table(data_for_crc)

                if received_crc != calculated_crc:
                    sys.stderr.write(f"extcap: CRC mismatch! Calculated {calculated_crc:04X}, Received {received_crc:04X}. Discarding packet.\n")
                    sys.stderr.flush()
                    partial_packet = partial_packet[1:] # Discard SOF_FLOAT and re-scan
                    continue # Try again with the truncated buffer

                # If we reach here, the packet is valid!
                sys.stderr.write(f"extcap: Valid packet received. Raw: {current_packet_candidate.hex().upper()}\n")
                sys.stderr.flush()

                # Extract the 13-byte SocketCAN frame
                # This is from buffer[2] to buffer[14] in your Teensy code
                socketcan_frame = current_packet_candidate[2 : 2 + SOCKETCAN_FRAME_LEN]
                
                fifo.write(socketcan_frame)
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
    
    # Custom arguments for our specific extcap
    parser.add_argument("--serial-port", required=False, help="Serial port to connect to (e.g., COM4 or /dev/ttyACM0)")
    parser.add_argument("--baudrate", type=int, default=115200, help="Serial baud rate (default: 115200)")

    args = parser.parse_args()

    if args.extcap_interfaces:
        print_extcap_interfaces()
    elif args.extcap_dlts:
        print_extcap_dlt()
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