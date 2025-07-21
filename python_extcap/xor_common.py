# common.py

SOF = 0x69  # Can still be used symbolically
INCLUDE_SOF_IN_CHECKSUM = True

def calculate_checksum(frame_bytes, checksum_index=-1):
    """
    XOR checksum for a frame.
    - `frame_bytes`: full buffer (including SOF and checksum byte).
    - `checksum_index`: where the checksum is stored. Defaults to last byte.
    """
    # Exclude the checksum byte itself from the calculation
    start_index = 0 if INCLUDE_SOF_IN_CHECKSUM else 1

    # Use a slice that excludes the checksum byte
    relevant = frame_bytes[start_index:checksum_index] + frame_bytes[checksum_index+1:]

    checksum = 0
    for b in relevant:
        checksum ^= b
    return checksum


def verify_frame_checksum(frame_bytes, checksum_index=-1):
    """
    Verifies checksum at `checksum_index` (default: last byte).
    Returns (is_valid, computed_checksum)
    """
    computed = calculate_checksum(frame_bytes, checksum_index=checksum_index)
    expected = frame_bytes[checksum_index]
    return (computed == expected), computed
