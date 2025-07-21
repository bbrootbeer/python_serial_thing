# serial_utils.py (or print_utils.py)
import sys

def print_frame(buf, label="Frame", color="green"):
    """
    Pretty prints a buffer with an optional label and color.
    """
    color_codes = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "reset": "\033[0m"
    }

    color_code = color_codes.get(color, "")
    reset_code = color_codes["reset"]

    hex_bytes = ' '.join(f'{b:02X}' for b in buf)
    print(f"{color_code}{label}: {hex_bytes}{reset_code}")
