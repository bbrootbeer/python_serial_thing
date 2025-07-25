# wtf is this xonxoff sheet

##

"XON/XOFF" is a type of flow control used in serial communication (like RS-232). It's a method for two devices communicating over a serial port to tell each other when to pause and resume sending data, preventing a faster device from overwhelming a slower one.

Here's a breakdown:

What is Flow Control?
Imagine you have a very fast talker (your computer) trying to send information to a very slow listener (like an old printer). Without any way to coordinate, the fast talker would just keep talking, and the slow listener would eventually miss words because its "ears" (input buffer) are full.

Flow control is simply the mechanism for the listener to tell the talker: "Hold on, I need a moment!" and then "Okay, I'm ready again!"

XON/XOFF: Software Flow Control
"XON/XOFF" is a type of software flow control. This means the signals to pause and resume are sent as special characters within the normal data stream (in-band signaling), using the same data lines that the actual information is flowing on.

XOFF (Transmit Off): When a receiving device (e.g., your computer's serial port buffer) is getting full and can't process any more incoming data immediately, it sends an XOFF character back to the transmitting device (e.g., your Teensy).

The XOFF character is typically ASCII DC3 (Device Control 3), which has a decimal value of 19 (or 0x13 in hexadecimal). On a keyboard, this is often Ctrl+S.

XON (Transmit On): Once the receiving device has cleared its buffer and is ready to accept more data, it sends an XON character back to the transmitting device.

The XON character is typically ASCII DC1 (Device Control 1), which has a decimal value of 17 (or 0x11 in hexadecimal). On a keyboard, this is often Ctrl+Q.

How it Works in Practice:
Sender (e.g., Teensy) starts transmitting data.

Receiver (e.g., PC's serial port buffer) starts receiving data.

Receiver's buffer fills up. When it reaches a certain threshold (a "high water mark"), the receiver sends an XOFF character to the sender.

Sender receives the XOFF character. It immediately stops transmitting data.

Receiver processes data. Its buffer starts to empty.

Receiver's buffer empties sufficiently (reaches a "low water mark"). The receiver sends an XON character to the sender.

Sender receives the XON character. It resumes transmitting data.

Advantages of XON/XOFF:
Fewer Wires: Only needs the basic Tx, Rx, and GND wires. No extra dedicated flow control wires are required, making simpler cables.

Disadvantages of XON/XOFF:
In-band Signaling: Since the XON/XOFF characters are sent on the same data lines, they cannot appear in your actual data without being misinterpreted as flow control commands. This makes it unsuitable for transmitting arbitrary binary data (like your CAN packets) unless you implement an "escaping" mechanism (where you replace actual 0x11 or 0x13 bytes in your data with a special sequence).

Latency: It takes time for the XOFF/XON character to be sent, received, and processed by software. During this delay, the sender might transmit a few more bytes after the receiver sent XOFF, potentially causing a small buffer overrun if the receiver's buffer is very small.

Reliability: If an XON or XOFF character gets corrupted or lost during transmission, the communication can get "stuck" (e.g., the sender stops and never gets an XON to resume, or the receiver keeps getting data it can't handle).

Other Types of Flow Control:
Hardware Flow Control (RTS/CTS, DTR/DSR): This is generally preferred for binary data. It uses dedicated wires (pins) on the serial port connector (like RTS - Request To Send, and CTS - Clear To Send). The voltage level on these wires is used to signal readiness, completely separate from the data lines. This is faster and doesn't interfere with your data.

In your case, since you're sending raw binary CAN data, XON/XOFF is generally not recommended unless you specifically designed an escaping mechanism into your Teensy's protocol. It's usually better to use no flow control and rely on your Python script to read fast enough, or (if supported by your hardware) use RTS/CTS hardware flow control if you run into buffer overruns on the PC side.







so wait... can my scripts (not sure if you remember them...) can be configured with this functionality?


Yes, absolutely! Your Python scripts using the pyserial library can be configured with XON/XOFF flow control functionality.

PySerial provides parameters to control flow control when you initialize the serial.Serial object.

How to Configure XON/XOFF in PySerial
You would set the xonxoff parameter to True when opening the serial port.

Here's an example:

Python

import serial
import sys
import time

SERIAL_PORT = '/dev/ttyACM0' # Or 'COMx' on Windows
BAUD_RATE = 115200

try:
    # Configure serial port with XON/XOFF flow control
    ser = serial.Serial(
        port=SERIAL_PORT,
        baudrate=BAUD_RATE,
        timeout=0.1,  # Read timeout
        xonxoff=True  # <<< This enables XON/XOFF software flow control
    )
    sys.stderr.write(f"extcap: Connected to serial port {SERIAL_PORT} with XON/XOFF flow control.\n")
    sys.stderr.flush()

    # --- Your reading loop would go here ---
    # Example: Just reading for a bit to demonstrate connection
    start_time = time.time()
    while (time.time() - start_time) < 10: # Read for 10 seconds
        data = ser.read_all()
        if data:
            sys.stderr.write(f"extcap: Received: {data.hex()}\n")
            sys.stderr.flush()
        else:
            time.sleep(0.01) # Small delay when no data
            
except serial.SerialException as e:
    sys.stderr.write(f"extcap: Error opening serial port {SERIAL_PORT}: {e}\n")
    sys.stderr.flush()
    sys.exit(1)
finally:
    if 'ser' in locals() and ser.is_open:
        ser.close()
        sys.stderr.write("extcap: Serial port closed.\n")
        sys.stderr.flush()

Important Caution for Your Use Case (Binary CAN Data)
While you can enable XON/XOFF, it's generally not recommended for your specific scenario of transmitting raw binary CAN data, unless you have a very robust escaping mechanism implemented on your Teensy and in your Python script.

As we discussed, XON/XOFF works by sending special characters (0x11 for XON and 0x13 for XOFF) within the data stream. If your actual CAN data bytes ever happen to contain 0x11 or 0x13, the receiving device (PySerial) will interpret them as flow control commands rather than part of your actual CAN message, leading to:

Data Corruption: Your CAN frames will be missing bytes or will have incorrect values.

Stalled Communication: The sender might stop unexpectedly if it thinks it received an XOFF, even though that 0x13 was part of your CAN ID or data.

For raw binary data, hardware flow control (RTS/CTS) is almost always the preferred method if your serial adapters and cables support it, as it uses separate physical wires and doesn't interfere with your data. If hardware flow control isn't an option, relying on no flow control and ensuring your Python script reads fast enough (like with the ser.read_all() and a small timeout we just discussed) is often the next best approach for continuous, high-speed binary streams.