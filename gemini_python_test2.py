import serial
import time

port = 'COM4' # Change to your COM port
baud_rate = 115200

print(f"Opening serial port {port} at {baud_rate}...")
try:
    ser = serial.Serial(port, baud_rate, timeout=1) # Timeout for initial connection, readline will handle its own timeouts
    print("Port opened successfully. Waiting for SLCAN data...")

    buffer = b'' # Use a bytes buffer for raw incoming data

    while True:
        # Read available bytes without blocking indefinitely
        incoming_byte = ser.read(1) # Read one byte at a time
        
        if incoming_byte:
            buffer += incoming_byte
            if incoming_byte == b'\r': # Check for carriage return
                line = buffer.decode('ascii').strip() # Decode and strip after receiving the full line
                buffer = b'' # Clear buffer for the next line

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
        # else:
        #     # If no incoming_byte, it means timeout was reached.
        #     # You can add a small delay here if you want to prevent
        #     # busy-waiting, but ser.read(1) with timeout=1 will naturally
        #     # yield if nothing is available.

except serial.SerialException as e:
    print(f"Error opening serial port: {e}")
except KeyboardInterrupt:
    print("\nExiting.")
finally:
    if 'ser' in locals() and ser.is_open:
        ser.close()
        print("Serial port closed.")