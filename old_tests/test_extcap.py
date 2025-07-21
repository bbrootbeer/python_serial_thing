#!/usr/bin/env python3
import sys
import struct
import time
import serial

# Your serial port config:
# PORT = "/dev/ttyUSB0"  # or COM4 on Windows
PORT = "COM4"
BAUD = 115200

# Your packet format constants:
SOF = 0x69
PACKET_LEN = 16  # bytes total (including SOF and checksum)

# opens specified port, at specified baud, and returns the output, basically the connection to the device
def open_serial(port, baud):
    return serial.Serial(port, baud, timeout=1)

def verify_checksum(packet):
    # XOR all bytes except SOF and checksum byte
    # packet is bytes-like of length PACKET_LEN
    checksum = 0
    # this is [:] slicing operator... it takes the "packet, or the bytearray() 'object'" and slices it
    # starting at position 1, but the exnding index on the right side, is not includsive... so i think this just says, don't include the checksum byte...
    # -1 is the end of the array i think, because it starts at 1 or -1... where if you start from the left, it start at 0...
    # so yeah i think this take the packet, removes SOF, and Checksum
    # im not sure if this needs to be "b" here... probably makes it confusing...
    # so byttee_rapper is just a variable name for each byte... was originally "b"
    for byte_verify_checksum_position in packet[1:-1]:
        checksum ^= byte_verify_checksum_position # x ^= y # This is equivalent to x = x ^ y, so here it means 0 = 0 ^  
    return checksum == packet[-1]

def parse_packet(packet):
    # packet: bytes-like, length 16
    # Returns dict with parsed fields or None if invalid
    if packet[0] != SOF:
        return None
    if not verify_checksum(packet):
        return None
    
    flags = packet[1]
    extended = bool(flags & 0x01)
    can_id = struct.unpack(">I", packet[2:6])[0]
    length = packet[6]
    data = packet[7:7+length]

    return {
        "extended": extended,
        "id": can_id,
        "length": length,
        "data": data
    }

def pcap_global_header():
    # "IHHiII" is a format string, for "struct.pack()" it tells python how to convert values to
    # "<" mean little endian byte
    # "I" is unsigned int (4 bytes)
    # "H" is unsigned short (2 bytes)
    # "i" is signed int (4 bytes)
    # PCAP global header for Ethernet linktype=147 (LINKTYPE_CAN_SOCKETCAN)
    # ref: https://wiki.wireshark.org/Development/LibpcapFileFormat
    # LINKTYPE_CAN_SOCKETCAN = 227
    return struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,  # magic number
        2,           # major version
        4,           # minor version
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        227          # network = CAN_SOCKETCAN
    )

def pcap_packet_header(ts_sec, ts_usec, incl_len, orig_len):
    return struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)

def build_can_socketcan_frame(parsed):
    # Format CAN frame like SocketCAN (16 bytes)
    # ref: https://www.kernel.org/doc/html/latest/networking/can.html#cmsg_can
    can_id = parsed["id"]
    if parsed["extended"]:
        # "0x80000000" is a hex numeber # in binary "1000 0000 0000 0000 0000 0000 0000 0000"
        # bit 31 is set to "1" in the example above
        can_id |= 0x80000000  # CAN_EFF_FLAG
    length = parsed["length"]
    data = parsed["data"] + bytes(8 - length)

    # can_frame struct: 4 bytes id, 1 byte length, 3 bytes padding, 8 bytes data
    # what is "<IB3x8s" in "struct.pack()"
    # "<" is little endian
    # "I" is 4-byte CAN ID
    # "B" 1-byte data length (DLC)
    # "3x" is 3 bytes padding
    # "8s" is 8 byte data field
    return struct.pack("<IB3x8s", can_id, length, data)

def main():
    # This calls your helper funtion above
    ser = open_serial(PORT, BAUD)

    # Write PCAP global header once
    # writes a 24 byte, global PCAP header to stdout, this is required once at the start of any .pcap file
    # this global PCAP header, defines the file as PCAP, sets the version and specifies the link type
    # in this case its "LINKTYPE_CAN_SOCKETCAN", and this is so wireshark can interpret frames...
    sys.stdout.buffer.write(pcap_global_header())
    sys.stdout.flush()

    #You're going to collect incoming serial bytes into this buf until you have a full 16-byte packet (the fixed format used in canTestCrack()).
    # FYI bytearray() is a BUILT IN PYTHON TYPE just like int str or list...
    # you do things like:
    # buf = bytearray()
    # buf.append(0x69)
    # buf += b'\x01\x02'
    # print(buf)  # bytearray(b'i\x01\x02')
    buf = bytearray() # this is a mutable list of bytes.... which you can .append() .pop() or slice... ect... unlike bytes, it's editable..

    try:
        while True:
            # this reads a single byte from serial, and if it's a timeout "b" is empty and it waits
            # basically b is "ser = open_serial(PORT, BAUD)" output...
            b = ser.read(1)
            if not b:
                continue
            # this adds a individual byte to buffer, remember buf = bytearray()
            buf += b
            # waits until buffer has full 16 bytes
            # this handles overflow and resync
            # remember buf = bytearray()
            # remember PACKET_LEN = 16
            if len(buf) < PACKET_LEN:
                continue
            if len(buf) > PACKET_LEN:
                # Remove bytes before SOF to resync if needed
                # this is a fancy way, of saying if bytearray() position 0 is not = SOF pop it off... and wait for that to happen
                # it also says if the position of bytearray() is less than 16 in case... keep on goin and adding bytes..
                # if somehow the program collected more than 16 bytes before processing, it tries to resync... by discarding, junk?
                while buf and buf[0] != SOF:
                    buf.pop(0)
                if len(buf) < PACKET_LEN:
                    continue

            # This turn the buffer, or bytearray() into a bytes object...
            # it then passes to parse_packet()
            packet = bytes(buf[:PACKET_LEN]) # buf[:PACKET_LEN] means take the first PACKET_LEN elements... if PACKET_LEN = 16, then this is buf[0:16]
            parsed = parse_packet(packet)
            if parsed is None:
                # Bad packet, resync by dropping first byte
                buf.pop(0)
                continue

            # Prepare PCAP packet
            ts = time.time()
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)

            can_frame = build_can_socketcan_frame(parsed)
            # incl_len is number of bytes actually captured
            # orig_len is number of bytes on the wire
            # These are the same for us, because we're capturing the whole thing... but in real networks you might drop bytes, so wireshakr wants both fields
            incl_len = orig_len = len(can_frame)

            pcap_hdr = pcap_packet_header(ts_sec, ts_usec, incl_len, orig_len)

            # Output PCAP packet header + packet
            sys.stdout.buffer.write(pcap_hdr + can_frame)
            sys.stdout.flush()

            # Remove processed bytes
            # i guess this trims the processed data fromt he front of the buffer...
            # if new data already came in while processing, it remains in buf...? isn't this bad?
            buf = buf[PACKET_LEN:]

    except KeyboardInterrupt:
        ser.close()

if __name__ == "__main__":
    main()
