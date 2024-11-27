def validate_message_length(udp_data, offset, expected_length, msg_type):
    remaining_bytes = len(udp_data) - offset
    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for '{msg_type}' message: needed {expected_length}, but only {remaining_bytes} available.")
        return False
    return True

def byte_to_char(byte_value):
    """Convert a single-byte value to a character."""
    if isinstance(byte_value, bytes):
        return byte_value.decode('ascii', errors='ignore')
    elif isinstance(byte_value, int):
        if 0 <= byte_value <= 255:
            return chr(byte_value)
        else:
            return '?'
    else:
        raise TypeError(f"Unexpected type {type(byte_value)} for single-byte value.")

def find_start_of_itch_message(udp_data, offset):
    """Locate a valid ITCH message type at or after the current offset."""
    valid_message_types = {
        'S', 'R', 'A', 'E', 'C', 'P', 'Q', 'H', 'Y', 'L', 'V', 'W', 'K', 'J',
        'h', 'F', 'X', 'D', 'U', 'B', 'I', 'O'
    }

    while offset < len(udp_data):
        potential_type = udp_data[offset:offset + 1].decode('ascii', errors='ignore')
        if potential_type in valid_message_types:
            print(f"[DEBUG] Found valid message type '{potential_type}' at offset {offset}")
            return offset
        else:
            print(f"[WARN] Skipping invalid byte '{udp_data[offset:offset + 1].hex()}' at offset {offset}")
        offset += 1

    print("[ERROR] No valid ITCH message type found in payload.")
    return None