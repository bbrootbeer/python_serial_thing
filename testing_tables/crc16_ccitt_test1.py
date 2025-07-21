def generate_crc16_ccitt_table(poly=0x1021):
    table = []
    for byte in range(256): # this goes from 0-255
        crc = byte << 8 # this << is what tell python to process the numbers as binary
        for _ in range(8): # here ```_``` is just a var, and it tells python i need to loop, but the variable is not needed
            if crc & 0x8000:
                # crc = (crc << 1) ^ poly
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
                # crc <<= 1
            # crc &= 0xFFFF  # Trim to 16 bits
        table.append(crc)
    return table

# crc0 = 0b00000000
#     if 0b0000000000000000 & 0b1000000000000000 (this is false)
#         0b0000000000000000
#
#    128 = 0b0000000010000000
# crc128 = 0b1000000000000000
#   poly = 0b0001000000100001
#          0b1001000000100001

# Print table in binary, 8 values per row
# for i in range(0, 256, 8):
#     row = ', '.join(f'0b{val:016b}' for val in table[i:i+8])
#     print(f'{row},')

# import csv
# with open("crc16_ccitt_table.csv", "w", newline="") as f:
#     writer = csv.writer(f)
#     writer.writerow(table)


# Print the table in C++ style for Teensy
# table = generate_crc16_ccitt_table()
# for i in range(0, 256, 8):
#     row = ', '.join(f'0x{val:04X}' for val in table[i:i+8])
#     print(f'{row},')

# import csv
# with open("crc16_ccitt_table.csv", "w", newline="") as f:
#     writer = csv.writer(f)
#     writer.writerow(table)

def write_crc_h(table, filename="crc16_ccitt_table.h"):
    with open(filename, "w") as f:
        f.write("#pragma once\n\n")
        # f.write("#ifndef CRC_TABLE_H\n#define CRC_TABLE_H\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write("// Auto-generated CRC-16 Table (CCITT)\n")
        f.write("const uint16_t crc16_table[256] = {\n")
        for i in range(0, 256, 8):
            line = ", ".join(f"0x{table[i+j]:04X}" for j in range(8))
            f.write(f"    {line},\n")
        f.write("};\n")
        # f.write("#endif // CRC_TABLE_H\n")


def write_crc_py(table, filename="crc16_ccitt_table.py"):
    with open(filename, "w") as f:
        f.write("# Auto-generated CRC-16 Table (CCITT)\n")
        f.write("crc16_table = [\n")
        for i in range(0, 256, 8):
            line = ", ".join(f"0x{table[i+j]:04X}" for j in range(8))
            f.write(f"    {line},\n")
        f.write("]\n")


if __name__ == "__main__":
    table = generate_crc16_ccitt_table()
    write_crc_h(table)
    write_crc_py(table)
    print("✅ Generated: crc_table.h and crc_table.py")
