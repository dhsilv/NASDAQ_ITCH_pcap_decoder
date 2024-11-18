import dpkt
import csv
import struct
from dataclasses import dataclass

@dataclass
class Message:
    msg_type: str
    fields: dict

def validate_message_length(udp_data, offset, expected_length, msg_type):
    """Validate if the buffer contains enough bytes for the given message type."""
    remaining_bytes = len(udp_data) - offset
    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for '{msg_type}' message: needed {expected_length}, but only {remaining_bytes} available.")
        return False
    return True

def find_start_of_itch_message(udp_data, offset):
    """Locate a valid ITCH message type at or after the current offset."""
    while offset < len(udp_data):
        potential_type = udp_data[offset:offset + 1].decode('ascii', errors='ignore')
        if potential_type in {'S', 'R', 'A', 'E', 'C', 'P', 'Q', 'H', 'Y', 'V', 'W', 'K', 'J', 'h'}:
            print(f"[DEBUG] Found valid message type '{potential_type}' at offset {offset}")
            return offset
        else:
            print(f"[WARN] Skipping invalid byte '{udp_data[offset:offset + 1].hex()}' at offset {offset}")
        offset += 1
    print("[ERROR] No valid ITCH message type found in payload.")
    return None

def system_event_message(udp_data, offset):
    expected_length = 11
    if not validate_message_length(udp_data, offset, expected_length, "S"):
        return None, len(udp_data)

    temp = struct.unpack_from(">HH6sc", udp_data, offset)
    return {
        "msg_type": "S",
        "stock_locate": temp[0],
        "tracking_number": temp[1],
        "timestamp": struct.unpack(">Q", b"\x00\x00" + udp_data[offset + 4:offset + 10])[0],
        "event_code": temp[3].decode('ascii', errors='ignore')
    }, offset + expected_length

def stock_directory_message(udp_data, offset):
    expected_length = 39
    if not validate_message_length(udp_data, offset, expected_length, "R"):
        return None, len(udp_data)

    temp = struct.unpack_from(">HH6s8scc", udp_data, offset)
    return {
        "msg_type": "R",
        "stock_locate": temp[0],
        "tracking_number": temp[1],
        "timestamp": struct.unpack(">Q", b"\x00\x00" + udp_data[offset + 4:offset + 10])[0],
        "stock": temp[3].decode('ascii', errors='ignore').strip(),
        "market_category": byte_to_char(temp[4]),
        "financial_status_indicator": byte_to_char(temp[5])
    }, offset + expected_length

def add_order_no_mpid(udp_data, offset):
    expected_length = 36
    if not validate_message_length(udp_data, offset, expected_length, "A"):
        return None, len(udp_data)

    temp = struct.unpack_from(">HH6sQIc8sI", udp_data, offset)
    print(f"[DEBUG] Unpacked A message values: {temp}")

    return {
        "msg_type": "A",
        "stock_locate": temp[0],
        "tracking_number": temp[1],
        "timestamp": struct.unpack(">Q", b"\x00\x00" + udp_data[offset + 4:offset + 10])[0],
        "order_ref_number": temp[3],
        "buy_sell_indicator": byte_to_char(temp[4]), 
        "shares": temp[5],
        "stock": temp[6].decode('ascii', errors='ignore').strip(),
        "price": temp[7] / 10000.0
    }, offset + expected_length

def order_executed_message(udp_data, offset):
    expected_length = 30
    if not validate_message_length(udp_data, offset, expected_length, "E"):
        return None, len(udp_data)

    temp = struct.unpack_from(">HH6sQI8s", udp_data, offset) # Defines how to interpret the data
    return {
        "msg_type": "E",
        "stock_locate": temp[0],
        "tracking_number": temp[1],
        "timestamp": struct.unpack(">Q", b"\x00\x00" + udp_data[offset + 4:offset + 10])[0],
        "order_ref_number": temp[3],
        "executed_shares": temp[4],
        "match_number": temp[5]
    }, offset + expected_length

def parse_itch_message(udp_data, offset=0):
    remaining_bytes = len(udp_data) - offset
    if remaining_bytes < 1:
        print(f"[ERROR] No bytes remaining to read message type at offset {offset}.")
        return None, len(udp_data)  # Skip to the end of the buffer

    msg_type = udp_data[offset:offset + 1].decode('ascii', errors='ignore')
    offset += 1

    if msg_type == "S":
        return system_event_message(udp_data, offset)
    elif msg_type == "R":
        return stock_directory_message(udp_data, offset)
    elif msg_type == "A":
        return add_order_no_mpid(udp_data, offset)
    elif msg_type == "E":
        return order_executed_message(udp_data, offset)
    else:
        print(f"[WARN] Unknown message type: {msg_type} at offset {offset - 1}")
        return None, len(udp_data)

def decode_pcap_itch(file_path, output_csv, packet_limit=100):
    """Decode ITCH messages from a PCAP file and output all fields to a CSV."""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        csv_file = open(output_csv, 'w', newline='')
        csv_writer = csv.writer(csv_file)

        csv_writer.writerow(['msg_type', 'fields'])

        packet_count = 0
        for timestamp, buf in pcap:
            if packet_count >= packet_limit:
                print(f"\n[INFO] Reached packet limit of {packet_limit}. Stopping processing.")
                break 

            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if not isinstance(ip.data, dpkt.udp.UDP):
                continue

            udp = ip.data
            udp_data = udp.data

            print(f"\n[DEBUG] Packet #{packet_count} at timestamp {timestamp:.6f}. Payload length: {len(udp_data)}")
            print(f"[DEBUG] Payload (hex): {udp_data.hex()}")

            offset = 0
            offset = find_start_of_itch_message(udp_data, offset)
            if offset is None:
                print(f"[ERROR] No valid ITCH message found in packet #{packet_count}.")
                continue

            while offset < len(udp_data):
                message, offset = parse_itch_message(udp_data, offset)
                if message is None:
                    print(f"[ERROR] Failed to parse message at offset {offset}.")
                    break

                # Log all fields to the console
                print(f"[INFO] Parsed Message: {message['msg_type']}, Fields: {message}")

                # Write all fields to CSV
                csv_writer.writerow([message['msg_type'], message])

        csv_file.close()
        print(f"\n[INFO] Decoding complete. Output saved to {output_csv}. Parsed {packet_count} packets.")

def byte_to_char(byte_value):
    """Convert a single-byte value to a character."""
    if isinstance(byte_value, bytes):  # If it's a bytes object, decode it
        return byte_value.decode('ascii', errors='ignore')
    elif isinstance(byte_value, int):
        if 0 <= byte_value <= 255:
            return chr(byte_value)
        else:
            print(f"[WARN] Invalid byte value {byte_value} for conversion to character.")
            return '?' # This is where I'm having issues - with the buy_sell_indicator field among others
    else:
        raise TypeError(f"Unexpected type {type(byte_value)} for single-byte value.")

if __name__ == '__main__':
    input_pcap = 'your_file.pcap' 
    output_csv = 'decoded_messages.csv'
    packet_limit = 100  # Set the packet limit to the first 100 packets
    decode_pcap_itch(input_pcap, output_csv, packet_limit)
