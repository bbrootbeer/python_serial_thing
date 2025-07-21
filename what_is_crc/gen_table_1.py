def generate_crc32_table(poly=0x04C11DB7):
    table = []
    for byte in range(256):
        crc = byte << 24
        for _ in range(8):
            if (crc & 0x80000000) != 0:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFF  # keep 32-bit
        table.append(crc)
    return table

# Generate and print the table
crc32_table = generate_crc32_table()
for i, val in enumerate(crc32_table):
    print(f"0x{val:08X},", end='')
    if (i + 1) % 8 == 0:
        print()
