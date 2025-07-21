import serial
import sys

PORT = "COM4"       # or "/dev/ttyUSB0" on Linux
BAUD = 115200
EOL = b"\r\n"

line = []
try:
    with serial.Serial(PORT, BAUD) as ser:
        while True:
            byte = ser.read(1)
            # byte = ser.read(16)
            if byte:
                line.append(byte.hex())
                if len(line) == 16:
                    print(" ".join(line))
                    line = []

except KeyboardInterrupt:
    print("\n[Stopped]")
except Exception as e:
    print(f"Error: {e}")



# 69 00 00 00 03 61 04 00 00 00 00 00 00 00 00 66
#
# 69
# 00 // 0000 0000 ^ 0000 i // byte 1
# 00
# 00
# 03
# 61
# 04
# 00
# 00
# 00
# 00
# 00
# 00
# 00
# 00
# 66