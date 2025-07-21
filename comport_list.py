from serial.tools import list_ports

def list_serial_ports():
    ports = list_ports.comports()
    if not ports:
        print("No serial devices found.")
        return

    print("Available COM ports:")
    for port in ports:
        print(f"{port.device} - {port.description}")

if __name__ == "__main__":
    list_serial_ports()
