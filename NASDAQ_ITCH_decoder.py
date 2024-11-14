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

    if msg_type == "S":  # System Event Message
        fields.update({
            "stock_locate": struct.unpack_from(">H", udp_data, offset)[0],
            "tracking_number": struct.unpack_from(">H", udp_data, offset + 2)[0],
            "timestamp": struct.unpack_from(">Q", b'\x00\x00' + udp_data[offset + 4:offset + 10])[0],
            "event_code": udp_data[offset + 10:offset + 11].decode('ascii', errors='ignore')
        })
        offset += 11

    elif msg_type == "R":  # Stock Directory Message
        fields.update({
            "stock_locate": struct.unpack_from(">H", udp_data, offset)[0],
            "tracking_number": struct.unpack_from(">H", udp_data, offset + 2)[0],
            "timestamp": struct.unpack_from(">Q", b'\x00\x00' + udp_data[offset + 4:offset + 10])[0],
            "stock": udp_data[offset + 10:offset + 18].decode('ascii', errors='ignore').strip(),
            "market_category": udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore'),
            "financial_status_indicator": udp_data[offset + 19:offset + 20].decode('ascii', errors='ignore'),
        })
        offset += 39

    return Message(msg_type, fields), offset

def decode_pcap_itch(file_path, output_csv):
    """Decode ITCH messages from a PCAP file and output to a CSV."""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        csv_file = open(output_csv, 'w', newline='')
        csv_writer = csv.writer(csv_file)

        csv_writer.writerow(['msg_type', 'fields'])

        packet_count = 0
        for timestamp, buf in pcap:
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if not isinstance(ip.data, dpkt.udp.UDP):
                continue

            udp = ip.data
            udp_data = udp.data

            print(f"\n[DEBUG] Packet #{packet_count} at timestamp {timestamp}. Payload length: {len(udp_data)}")
            print(f"[DEBUG] Payload (hex): {udp_data.hex()}")

            offset = 0
            while offset < len(udp_data):
                message, offset = parse_itch_message(udp_data, offset)
                if message is None:
                    break
                csv_writer.writerow([message.msg_type, message.fields])

        csv_file.close()
        print(f"\n[INFO] Decoding complete. Output saved to {output_csv}. Parsed {packet_count} packets.")

if __name__ == '__main__':
    input_pcap = 'file_path.pcap'  # Replace with your actual input PCAP file
    output_csv = 'decoded_messages.csv'
    decode_pcap_itch(input_pcap, output_csv)
