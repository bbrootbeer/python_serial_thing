for byte in range(256): # this goes from 0-255
    counter = byte
    crc1 = byte << 0
    crc2 = byte << 8 # this << is what tell python to process the numbers as binary
    # print(f"byte: {byte:2} | crc (hex): 0x{crc:04X} | crc (bin): {crc:016b}")
    print (f"crc1 binary: {crc1:016b} | crc2 binary: {crc2:016b} | counter numebr {byte}")

# crc1 binary: 0000000000000000 | crc2 binary: 0000000000000000
# crc1 binary: 0000000000000001 | crc2 binary: 0000000100000000
# crc1 binary: 0000000000000010 | crc2 binary: 0000001000000000
# crc1 binary: 0000000000000011 | crc2 binary: 0000001100000000
# crc1 binary: 0000000000000100 | crc2 binary: 0000010000000000
# crc1 binary: 0000000000000101 | crc2 binary: 0000010100000000