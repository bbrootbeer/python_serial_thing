import serial
import time

port = 'COM4' # Change to your COM port
baud_rate = 115200

print(f"Opening serial port {port} at {baud_rate}...")
try:
    ser = serial.Serial(port, baud_rate, timeout=1)
    print("Port opened successfully. Waiting for SLCAN data...")

    while True:
        line = ser.readline().decode('ascii').strip()
        if line.startswith('t') or line.startswith('T'):
            try:
                frame_type = line[0]
                parts = line[1:].split('#')
                if len(parts) == 2:
                    can_id_str = parts[0]
                    can_data_str = parts[1]

                    can_id = int(can_id_str, 16)
                    data_bytes = []
                    for i in range(0, len(can_data_str), 2):
                        byte_hex = can_data_str[i:i+2]
                        data_bytes.append(int(byte_hex, 16))

                    print(f"Received: Type={frame_type}, ID=0x{can_id:X}, Len={len(data_bytes)}, Data={[f'{b:02X}' for b in data_bytes]}, ASCII='{''.join([chr(b) if 32 <= b <= 126 else '.' for b in data_bytes])}'")
                else:
                    print(f"Malformed SLCAN line (no hash or too many): {line}")
            except ValueError as e:
                print(f"Error parsing line: {line} - {e}")
        elif line: # If it's not a CAN message but still has content
            print(f"Other serial output: {line}")

except serial.SerialException as e:
    print(f"Error opening serial port: {e}")
except KeyboardInterrupt:
    print("\nExiting.")
finally:
    if 'ser' in locals() and ser.is_open:
        ser.close()
        print("Serial port closed.")