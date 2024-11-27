import dpkt
import csv
import struct
from dataclasses import dataclass
from itch_parsers import (
    order_executed_with_price_message,
    order_cancel_message,
    order_delete_message,
    order_replace_message,
    broken_trade_message,
    net_order_imbalance_indicator_message,
    retail_price_improvement_indicator_message,
    system_event_message,
    stock_directory_message,
    add_order_no_mpid,
    order_executed_message,
    cross_trade_message, 
    stock_trading_action_message,
    non_cross_trade_message,
    luld_auction_collar_message,
    short_sale_price_test_message,
    market_participation_position_message,
    mwcb_decline_level_message,
    mwcb_status_message,
    ipo_quoting_period_update_message,
    operational_halt_message,
    add_order_with_mpid_message
)
from utils import find_start_of_itch_message

@dataclass
class Message:
    msg_type: str
    fields: dict


def parse_itch_message(udp_data, offset=0):
    remaining_bytes = len(udp_data) - offset
    if remaining_bytes < 1:
        print(f"[ERROR] No bytes remaining to read message type at offset {offset}.")
        return None, len(udp_data)

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
    elif msg_type == "Q":
        return cross_trade_message(udp_data, offset)
    elif msg_type == "H":  
        return stock_trading_action_message(udp_data, offset)
    elif msg_type == "P": 
        return non_cross_trade_message(udp_data, offset)
    elif msg_type == "J": 
        return luld_auction_collar_message(udp_data, offset)
    elif msg_type == "Y":
        return short_sale_price_test_message(udp_data, offset)
    elif msg_type == "L":
        return market_participation_position_message(udp_data, offset)
    elif msg_type == "V":
        return mwcb_decline_level_message(udp_data, offset)
    elif msg_type == "W":
        return mwcb_status_message(udp_data, offset)
    elif msg_type == "K":
        return ipo_quoting_period_update_message(udp_data, offset)
    elif msg_type == "h":
        return operational_halt_message(udp_data, offset)
    elif msg_type == "F":
        return add_order_with_mpid_message(udp_data, offset)
    elif msg_type == "C":
        return order_executed_with_price_message(udp_data, offset)
    elif msg_type == "X":
        return order_cancel_message(udp_data, offset)
    elif msg_type == "D":
        return order_delete_message(udp_data, offset)
    elif msg_type == "U":
        return order_replace_message(udp_data, offset)
    elif msg_type == "B":
        return broken_trade_message(udp_data, offset)
    elif msg_type == "I":
        return net_order_imbalance_indicator_message(udp_data, offset)
    elif msg_type == "O":
        return retail_price_improvement_indicator_message(udp_data, offset)
    else:
        print(f"[WARN] Unknown message type: {msg_type} at offset {offset - 1}")
        return None, len(udp_data)

def decode_pcap_itch(file_path, output_csv, packet_limit=100):
    """Decode ITCH messages from a PCAP file and output all fields to a CSV."""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        csv_file = open(output_csv, 'w', newline='')
        csv_writer = csv.writer(csv_file)

        headers = [
            'msg_type', 'stock_locate', 'tracking_number', 'timestamp', 
            'order_ref_number', 'executed_shares', 'match_number'
        ]
        csv_writer.writerow(headers)

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

            offset = 0
            offset = find_start_of_itch_message(udp_data, offset)
            if offset is None:
                continue

            while offset < len(udp_data):
                message, offset = parse_itch_message(udp_data, offset)
                if message is None:
                    break

                row = [
                    message.get('msg_type', ''),
                    message.get('stock_locate', ''),
                    message.get('tracking_number', ''),
                    message.get('timestamp', ''),
                    message.get('order_ref_number', ''),
                    message.get('executed_shares', ''),
                    message.get('match_number', '')
                ]
                csv_writer.writerow(row)

        csv_file.close()
        print(f"\n[INFO] Decoding complete. Output saved to {output_csv}. Parsed {packet_count} packets.")
    """Decode ITCH messages from a PCAP file and output all fields to a CSV."""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        csv_file = open(output_csv, 'w', newline='')
        csv_writer = csv.writer(csv_file)

        # Write header for CSV dynamically based on all possible fields
        headers = [
            'msg_type', 'stock_locate', 'tracking_number', 'timestamp', 'event_code',
            'order_ref_number', 'buy_sell_indicator', 'shares', 'stock', 'price',
            'market_category', 'financial_status_indicator', 'executed_shares', 'match_number'
        ]
        csv_writer.writerow(headers)

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

            offset = 0
            offset = find_start_of_itch_message(udp_data, offset)
            if offset is None:
                continue

            while offset < len(udp_data):
                message, offset = parse_itch_message(udp_data, offset)
                if message is None:
                    break

                # Prepare row based on parsed message fields
                row = [message.get(key, '') for key in headers]
                csv_writer.writerow(row)

        csv_file.close()
        print(f"\n[INFO] Decoding complete. Output saved to {output_csv}. Parsed {packet_count} packets.")


if __name__ == '__main__':
    input_pcap = 'C:\\Users\\dansi\\OneDrive\\School\\CS\\HFT\\HFTRepo\\sample_NASDAQ_ITCH.pcap' 
    output_csv = 'decoded_messages.csv'
    packet_limit = 10
    decode_pcap_itch(input_pcap, output_csv, packet_limit)
