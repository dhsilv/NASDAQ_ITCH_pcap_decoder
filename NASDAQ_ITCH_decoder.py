import dpkt
import csv
import struct
from dataclasses import dataclass

@dataclass
class Message:
    msg_type: str
    fields: dict

def find_start_of_itch_message(udp_data, offset):
    """Locate a valid ITCH message type at or after the current offset."""
    while offset < len(udp_data):
        potential_type = udp_data[offset:offset + 1].decode('ascii', errors='ignore')
        if potential_type in {'S', 'R', 'A', 'E', 'C', 'P', 'Q', 'H', 'Y', 'V', 'W', 'K', 'J', 'h'}:
            return offset  # Found a valid ITCH message type
        offset += 1
    return None  # No valid ITCH message type found

def decode_pcap_itch(file_path, output_csv, packet_limit=100):
    """Decode ITCH messages from a PCAP file and output to a CSV."""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        csv_file = open(output_csv, 'w', newline='')
        csv_writer = csv.writer(csv_file)

        # Write header for CSV
        csv_writer.writerow(['msg_type', 'fields', 'stock_symbol'])

        packet_count = 0
        for timestamp, buf in pcap:
            if packet_count >= packet_limit:
                print(f"\n[INFO] Reached packet limit of {packet_limit}. Stopping processing.")
                break  # Stop after processing the specified number of packets

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
            while offset < len(udp_data):
                message, offset = parse_itch_message(udp_data, offset)
                if message is None:
                    break

                # Extract stock symbol if available
                stock_symbol = message.fields.get("stock", "N/A")
                print(f"[INFO] Parsed Message: {message.msg_type}, Stock: {stock_symbol}")

                # Write to CSV
                csv_writer.writerow([message.msg_type, message.fields, stock_symbol])

        csv_file.close()
        print(f"\n[INFO] Decoding complete. Output saved to {output_csv}. Parsed {packet_count} packets.")

def parse_itch_message(udp_data, offset=0):
    """
    Parse an individual ITCH message from the given UDP payload data starting at the specified offset.
    """
    offset = find_start_of_itch_message(udp_data, offset)
    if offset is None:
        return None, len(udp_data)  # End of valid messages in the payload
    
    msg_type = udp_data[offset:offset + 1].decode('ascii')
    offset += 1

    fields = {"msg_type": msg_type}

    # Parse specific message types
    if msg_type == "S":  # System Event Message
        # Ensure the timestamp slice is valid
        timestamp_slice = udp_data[offset + 4:offset + 10]
        if len(timestamp_slice) != 6:
            print(f"[ERROR] Timestamp slice has incorrect length: {len(timestamp_slice)}. Skipping message.")
            return None, len(udp_data)

        fields.update({
            "stock_locate": struct.unpack_from(">H", udp_data, offset)[0],
            "tracking_number": struct.unpack_from(">H", udp_data, offset + 2)[0],
            "timestamp": struct.unpack(">Q", b'\x00\x00' + timestamp_slice)[0],
            "event_code": udp_data[offset + 10:offset + 11].decode('ascii', errors='ignore')
        })
        offset += 11

    elif msg_type == "R":  # Stock Directory Message
        # Ensure the timestamp slice is valid
        timestamp_slice = udp_data[offset + 4:offset + 10]
        if len(timestamp_slice) != 6:
            print(f"[ERROR] Timestamp slice has incorrect length: {len(timestamp_slice)}. Skipping message.")
            return None, len(udp_data)

        stock_bytes = udp_data[offset + 10:offset + 18]
        fields.update({
            "stock_locate": struct.unpack_from(">H", udp_data, offset)[0],
            "tracking_number": struct.unpack_from(">H", udp_data, offset + 2)[0],
            "timestamp": struct.unpack(">Q", b'\x00\x00' + timestamp_slice)[0],
            "stock": stock_bytes.decode('ascii', errors='ignore').strip(),
            "market_category": udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore'),
            "financial_status_indicator": udp_data[offset + 19:offset + 20].decode('ascii', errors='ignore'),
        })
        offset += 39

    # Add more message types as needed...
    return Message(msg_type, fields), offset

if __name__ == '__main__':
    input_pcap = 'file_name.pcap' 
    output_csv = 'decoded_messages.csv'
    packet_limit = 100  # Set the packet limit to the first 100 packets
    decode_pcap_itch(input_pcap, output_csv, packet_limit)
