# some interesting "dlt" information

## dlt info

Wireshark DLTs for CAN
Does Wireshark have ANY DLTs CAN related... that are not, 227?

Yes, absolutely! While DLT_SOCKETCAN (227) is very common on Linux and is what your script uses, Wireshark supports several other DLTs for CAN-related traffic:

DLT_CAN_SOCKET (227): This is the one you're using. It represents the struct can_frame from Linux SocketCAN, which includes the CAN ID, DLC, and 8 bytes of data. It's widely used because SocketCAN is the de facto standard for CAN on Linux.

DLT_CAN_LOG (228): This DLT is designed for logging raw CAN frames with additional metadata, such as timestamps and error flags, directly from the CAN driver. It provides more detail than just the basic CAN frame.

DLT_ISO_TP (165): While not purely a CAN DLT, ISO-TP (ISO 15765-2) is a transport protocol often used over CAN (and other networks like FlexRay, LIN). This DLT is for capturing and dissecting ISO-TP segments, which can span multiple CAN frames to send larger messages (e.g., for UDS diagnostics).

DLT_J1939 (237): J1939 is a high-level protocol used in heavy-duty vehicles over CAN. This DLT is specifically for J1939 messages, allowing Wireshark to dissect its complex parameter group numbers (PGNs), source/destination addresses, and data fields.

DLT_VSAN (124): This is a vendor-specific DLT used by Vector Informatik tools (e.g., CANoe, CANape) for their proprietary logging format. While it's not an open standard, Wireshark has dissectors for it to allow users of Vector tools to analyze their logs.

So, while DLT_SOCKETCAN is perfect for what your script is doing (translating your serial protocol to a standard CAN frame), it's important to know that Wireshark is much broader in its CAN support.

## a note about k-line and why it's NOT a DLT

You're absolutely right to find the other DLTs interesting! Automotive diagnostics and communication protocols are a fascinating and deep rabbit hole. CAN, ISO-TP, J1939, and the like represent layers of increasing complexity and specialization on top of the raw electrical signals.

K-Line (ISO 9141-2 / ISO 14230-4 KWP2000) DLT in Wireshark
For K-Line, which is typically associated with ISO 9141-2 and ISO 14230-4 (Keyword Protocol 2000 - KWP2000), there isn't a single, dedicated, standard DLT value like DLT_SOCKETCAN (227) or DLT_J1939 (237) that directly represents the raw K-Line physical layer in Wireshark's standard distribution.

Here's why and what you typically do:

Serial Communication: K-Line is fundamentally a serial communication protocol that operates over a single wire (plus ground). It's very similar to RS-232 serial, but with specific voltage levels and timing requirements for automotive use.

No Dedicated DLT for Raw K-Line: Wireshark's standard DLTs for serial communication are typically for generic serial (DLT_SERIAL_HDLC, DLT_LINUX_SLL, etc.) or for specific serial-based protocols like USB or PPP. There isn't a pre-defined DLT that says "this is raw K-Line bytes."

How it's usually captured and dissected:

Serial Interface Capture: To capture K-Line, you usually need a hardware interface that can convert the K-Line signals (which are typically 0V or 12V, and may have specific initialization sequences like the 5-baud init) into standard PC serial data (RS-232 or USB-CDC). Tools like an OBD-II interface with K-Line support (e.g., based on an ELM327 chip, though ELM327 primarily focuses on higher-level OBD-II PIDs) or custom hardware with a K-Line transceiver (like an L9637D or MC33199/33290) connected to a microcontroller that then outputs data over USB serial are common.

"Decode As" or Custom Dissectors: Once you get the raw K-Line bytes into Wireshark (often by capturing the standard serial port output, typically using DLT_USER0 through DLT_USER15 or a generic DLT_SERIAL_NO_FCS), you then need to tell Wireshark to interpret those bytes as ISO 9141-2 or KWP2000.

"Decode As" Feature: Wireshark's "Decode As" feature (found by right-clicking a packet) allows you to instruct Wireshark to apply a specific protocol dissector to a generic stream of bytes. You would typically tell it to "Decode As" ISO 9141 or KWP2000.

Custom Lua/C Dissector: For more complex or proprietary K-Line variants, you might need to write a custom Wireshark dissector in Lua or C that specifically understands the K-Line initialization sequences, message formats, and checksums. This custom dissector would then tell Wireshark how to parse the byte stream coming from your serial capture.

In summary for K-Line:

You won't find a DLT_KLINE directly. Instead, you'll capture the underlying serial data (often with a generic serial DLT or a DLT_USER* for custom setups) and then instruct Wireshark to dissect it using its built-in ISO 9141 or KWP2000 dissectors, or provide your own custom dissector if the protocol is non-standard.

It's a different beast than CAN, as CAN has its own dedicated physical layer (differential twisted pair) and a well-defined frame structure (DLT_SOCKETCAN covers this cleanly), whereas K-Line is more of a single-wire serial bus with higher-level protocols running on top.

But you're right, exploring these different automotive protocols like ISO-TP and K-Line is incredibly interesting for understanding how vehicle systems communicate! And yes, finish your current project – the satisfaction of getting that DLT_SOCKETCAN pipeline working perfectly will be immense.