import sys
import argparse

def xor_checksum(buffer, include_sof):
    start_idx = 0 if include_sof else 1
    checksum = 0x00
    for b in buffer[start_idx:63]:  # assuming 64-byte buffer, last byte checksum
        checksum ^= b
    return checksum

def parse_frame(frame_bytes, include_sof):
    # frame_bytes should be a bytes or bytearray of length 64

    # Calculate checksum
    calc_checksum = xor_checksum(frame_bytes, include_sof)
    frame_checksum = frame_bytes[63]

    # Validate checksum
    valid = (calc_checksum == frame_checksum)

    # For demo, print frame & validity
    print(f"Frame: {' '.join(f'{b:02X}' for b in frame_bytes)}")
    print(f"Checksum calc: {calc_checksum:02X}, Frame checksum: {frame_checksum:02X}, Valid: {valid}")
    print()

def main():
    parser = argparse.ArgumentParser(description="CAN extcap parser with optional SOF checksum inclusion")
    parser.add_argument("--include-sof", action="store_true",
                        help="Include SOF (first byte) in XOR checksum calculation")
    parser.add_argument("inputfile", nargs="?", type=argparse.FileType('rb'), default=sys.stdin.buffer,
                        help="Input file or stdin (binary frame stream)")

    args = parser.parse_args()

    include_sof = args.include_sof

    # Example: read frames in chunks of 64 bytes
    while True:
        frame = args.inputfile.read(64)
        if len(frame) < 64:
            break  # EOF or incomplete frame
        parse_frame(frame, include_sof)

if __name__ == "__main__":
    main()
