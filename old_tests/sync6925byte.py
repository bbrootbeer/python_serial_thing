import serial
import struct

PORT = "COM4"  # Update as needed
BAUD = 115200
SOF = 0x69
FRAME_SIZE = 25

def read_frame(ser):
    """Sync to SOF and read a full 25-byte frame."""
    while True:
        byte = ser.read(1)
        if not byte:
            continue
        if byte[0] == SOF:
            rest = ser.read(FRAME_SIZE - 1)
            if len(rest) == FRAME_SIZE - 1:
                return bytes([SOF]) + rest

def parse_frame(frame):
    """Parse your 25-byte custom CAN frame."""
    if len(frame) != FRAME_SIZE:
        return None

    sof = frame[0]
    timestamp = int.from_bytes(frame[1:5], 'little')
    can_id = int.from_bytes(frame[5:9], 'little')
    dlc = frame[9]
    data = frame[13:13+dlc]
    crc_received = int.from_bytes(frame[21:25], 'little')

    # Recalculate CRC over frame[1:21]
    import zlib
    crc_calculated = zlib.crc32(frame[1:21]) ^ 0xFFFFFFFF

    valid_crc = crc_received == crc_calculated

    return {
        'timestamp': timestamp,
        'can_id': can_id,
        'dlc': dlc,
        'data': data,
        'crc_valid': valid_crc,
    }

try:
    with serial.Serial(PORT, BAUD, timeout=1) as ser:
        while True:
            frame = read_frame(ser)
            parsed = parse_frame(frame)
            if parsed:
                print(f"ID: {hex(parsed['can_id'])}, Len: {parsed['dlc']}, Data: {parsed['data'].hex()}, CRC: {'OK' if parsed['crc_valid'] else 'BAD'}")
except KeyboardInterrupt:
    print("\n[Stopped]")
except Exception as e:
    print(f"Error: {e}")
