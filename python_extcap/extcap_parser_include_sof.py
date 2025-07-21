import sys

def parse_frame_include_sof(frame_bytes):
    # frame_bytes is a bytes object representing the full 64-byte frame
    # XOR checksum includes the first byte (SOF)
    checksum = 0
    for b in frame_bytes[:-1]:  # exclude last byte where checksum is stored
        checksum ^= b
    expected_checksum = frame_bytes[-1]
    valid = (checksum == expected_checksum)
    return valid, checksum

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        # Assume input line is hex string representing 64 bytes separated by spaces
        try:
            frame_bytes = bytes(int(b, 16) for b in line.split())
        except ValueError:
            print("Invalid input line", file=sys.stderr)
            continue

        valid, checksum = parse_frame_include_sof(frame_bytes)

        # Output parsing result for extcap/Wireshark
        print(f"Frame: {line} Checksum: {checksum:02X} Valid: {valid}")

if __name__ == "__main__":
    main()
