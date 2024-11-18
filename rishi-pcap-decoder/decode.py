from scapy.all import rdpcap
import struct
import csv


def parse_add_order_no_mpid(data):

    message_type, stock_locate, tracking_number, timestamp, order_ref, \
    buy_sell_indicator, shares, stock, price = struct.unpack('!cHHLQ1sI8sI', data)
    return {
        "message_type": message_type.decode(),
        "stock_locate": stock_locate,
        "tracking_number": tracking_number,
        "timestamp": timestamp,
        "order_ref": order_ref,
        "buy_sell_indicator": buy_sell_indicator.decode(),
        "shares": shares,
        "stock": stock.decode().strip(),
        "price": price / 10000  
    }

def parse_modify_order(data):

    message_type, stock_locate, tracking_number, timestamp, order_ref, \
    shares, price = struct.unpack('!cHHLQI', data)
    return {
        "message_type": message_type.decode(),
        "stock_locate": stock_locate,
        "tracking_number": tracking_number,
        "timestamp": timestamp,
        "order_ref": order_ref,
        "shares": shares,
        "price": price / 10000  
    }

def parse_delete_order(data):

    message_type, stock_locate, tracking_number, timestamp, order_ref = struct.unpack('!cHHLQ', data)
    return {
        "message_type": message_type.decode(),
        "stock_locate": stock_locate,
        "tracking_number": tracking_number,
        "timestamp": timestamp,
        "order_ref": order_ref
    }

def parse_trade_execution(data):

    message_type, stock_locate, tracking_number, timestamp, order_ref, \
    shares, price = struct.unpack('!cHHLQIQ', data)
    return {
        "message_type": message_type.decode(),
        "stock_locate": stock_locate,
        "tracking_number": tracking_number,
        "timestamp": timestamp,
        "order_ref": order_ref,
        "shares": shares,
        "price": price / 10000  
    }


packets = rdpcap("subset.pcap")
parsed_messages = []

for packet in packets:

    if packet.haslayer('UDP'):
        payload = bytes(packet['UDP'].payload) 
        print(f"Packet length: {len(payload)} bytes")
        print(f"Payload: {payload[:40]}...") 

        if len(payload) > 0:
            message_type = payload[0:1] 
            print(f"Message Type: {message_type}")

            try:
                if message_type == b'A':  # Add Order - No MPID Attribution
                    parsed_message = parse_add_order_no_mpid(payload)
                elif message_type == b'U':  # Modify Order
                    parsed_message = parse_modify_order(payload)
                elif message_type == b'D':  # Delete Order
                    parsed_message = parse_delete_order(payload)
                elif message_type == b'P':  # Trade Execution
                    parsed_message = parse_trade_execution(payload)
                else:
                    print(f"Unsupported message type: {message_type}")
                    continue  


                parsed_messages.append(parsed_message)
            except struct.error as e:
                print(f"Error parsing message of type {message_type.decode()}: {e}")
                print(f"Problematic payload: {payload}")
                continue


with open("parsed_itch_messages.csv", "w", newline="") as csvfile:

    fieldnames = ["message_type", "stock_locate", "tracking_number", "timestamp",
                  "order_ref", "buy_sell_indicator", "shares", "stock", "price"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)


    writer.writeheader()


    for message in parsed_messages:
        writer.writerow(message)

print("Parsed messages have been written to parsed_itch_messages.csv")
