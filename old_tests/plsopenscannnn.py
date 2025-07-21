import serial

ser = serial.Serial("COM4", 115200)

while True:
    frame = ser.read(16)  # Read one full CAN frame (SocketCAN format)

    can_id = int.from_bytes(frame[0:4], 'little')
    dlc = frame[4]
    data = frame[8:8+dlc]

    print(f"ID: {hex(can_id)}  DLC: {dlc}  Data: {' '.join(f'{b:02X}' for b in data)}")
