def main():
    while True:
        try:
            user_input = input("Enter a number (bin=0b..., hex=0x..., dec=...): ").strip()
            if user_input.lower() in ["exit", "quit"]:
                break

            num = int(user_input, 0)

            print(f"Decimal: {num}")
            print(f"Hex (8-bit):  0x{num & 0xFF:02X}")
            print(f"Hex (16-bit): 0x{num & 0xFFFF:04X}")
            print(f"Binary (8-bit):  0b{num & 0xFF:08b}")
            print(f"Binary (16-bit): 0b{num & 0xFFFF:016b}")
            print(f"Octal:    0o{num:o}")
            print()
        except ValueError:
            print("Invalid number. Try again (e.g., 42, 0x2A, 0b101010).\n")

if __name__ == "__main__":
    main()
