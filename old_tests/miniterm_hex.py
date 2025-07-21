import serial
import sys

PORT = "COM3"       # or "/dev/ttyUSB0" on Linux
BAUD = 115200
EOL = b"\r\n"

try:
    with serial.Serial(PORT, BAUD) as ser:
        while True:
            data = ser.read(1)
            if data:
                # Echo raw data to console
                # sys.stdout.buffer.write(data)
                # sys.stdout.flush()
                print(f"{data.hex()} ", end="", flush=True)
except KeyboardInterrupt:
    print("\n[Stopped]")
except Exception as e:
    print(f"Error: {e}")
