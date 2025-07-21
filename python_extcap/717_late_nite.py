import serial
import time
from print_utils import print_frame
from serial_utils import choose_serial_port, find_frame_start
from can_parser import parse_frame_exclude_sof  # your CAN frame parser

def main():
    port = choose_serial_port()
    ser = serial.Serial(port, baudrate=115200, timeout=0.1)

    buffer = bytearray()
    FRAME_SIZE = 64  # or your actual frame size

    while True:
        data = ser.read(128)  # read up to 128 bytes at a time
        if data:
            buffer.extend(data)

            # Look for a valid frame in the buffer
            idx = find_frame_start(buffer, parse_frame_exclude_sof)
            if idx >= 0:
                frame = buffer[idx:idx+FRAME_SIZE]
                print_frame(frame, label="CAN Frame")
                # Remove processed frame from buffer
                buffer = buffer[idx+FRAME_SIZE:]
        else:
            time.sleep(0.01)

if __name__ == "__main__":
    main()
