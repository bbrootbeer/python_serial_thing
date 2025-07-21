import serial
import serial.tools.list_ports
import sys

def parse_frame_exclude_sof(frame_bytes):
    checksum = 0
    for b in frame_bytes[1:-1]:  # exclude SOF and checksum
        checksum ^= b
    expected_checksum = frame_bytes[-1]
    valid = (checksum == expected_checksum)
    return valid, checksum

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

def main():
    port = choose_serial_port()
    ser = serial.Serial(port, baudrate=115200, timeout=1)

    print(f"Reading from {port}...")

    while True:
        frame_bytes = ser.read(64)
        if len(frame_bytes) < 64:
            continue  # skip incomplete frames

        valid, checksum = parse_frame_exclude_sof(frame_bytes)
        print(f"Checksum: {checksum:02X} Valid: {valid}")

if __name__ == "__main__":
    main()
