import serial
from xor_common import SOF, FRAME_SIZE, verify_frame_checksum
from serial_utils import choose_serial_port, find_frame_start
from print_utils import print_frame


def parse_frame_exclude_sof(frame_bytes):
    """
    Wrapper around verify_frame_checksum to maintain same interface.
    Returns (valid, checksum)
    """
    valid, checksum = verify_frame_checksum(frame_bytes)
    return valid, checksum


def main():
    port = choose_serial_port()
    ser = serial.Serial(port, baudrate=115200, timeout=1)
    print(f"Reading from {port}...")

    buffer = bytearray()

    while True:
        data = ser.read(128)
        buffer.extend(data)

        while len(buffer) >= FRAME_SIZE:
            if buffer[0] != SOF:
                offset = find_frame_start(buffer, parse_frame_exclude_sof)
                if offset == -1:
                    buffer = buffer[-FRAME_SIZE:]  # discard junk
                    break
                else:
                    buffer = buffer[offset:]

            frame = buffer[:FRAME_SIZE]
            valid, checksum = parse_frame_exclude_sof(frame)
            color = "green" if valid else "red"
            print_frame(frame, label=f"Checksum {checksum:02X} Valid={valid}", color=color)

            if valid:
                buffer = buffer[FRAME_SIZE:]
            else:
                buffer = buffer[1:]  # try to resync


if __name__ == "__main__":
    main()
