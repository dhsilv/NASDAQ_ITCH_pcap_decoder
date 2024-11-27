import struct
from utils import validate_message_length, byte_to_char, find_start_of_itch_message




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

    stock_raw_data = udp_data[offset + 12:offset + 20] 

    try:
        stock = stock_raw_data.decode('ascii').strip() 
        print(f"Stock symbol: {stock}")
    except UnicodeDecodeError as e:
        print(f"Error decoding stock symbol: {e}")
        stock = ""

    

    stock_raw_data = udp_data[offset + 12:offset + 20]

    try:
        stock = stock_raw_data.decode('ascii').strip() 
        print(f"Stock symbol: {stock}")
    except UnicodeDecodeError as e:
        print(f"Error decoding stock symbol: {e}")
        stock = ""

    
    return {
        "msg_type": "R",
        "stock_locate": temp[0],
        "tracking_number": temp[1],
        "timestamp": struct.unpack(">Q", b"\x00\x00" + udp_data[offset + 4:offset + 10])[0],
        # "stock": temp[3].decode('ascii', errors='ignore').strip(),
        "stock": stock,
        "stock": stock,
        "market_category": byte_to_char(temp[4]),
        "financial_status_indicator": byte_to_char(temp[5])
    }, offset + expected_length

def add_order_no_mpid(udp_data, offset):
    """
    Parse the 'A' (Add Order No MPID) message according to the ITCH protocol.
    """
    expected_length = 36  
    remaining_bytes = len(udp_data) - offset

    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for 'A' message: needed {expected_length}, but only {remaining_bytes} available at offset {offset}.")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset + 1:offset + 3], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 3:offset + 5], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 5:offset + 11], byteorder="big", signed=False)
        order_ref_number = int.from_bytes(udp_data[offset + 11:offset + 19], byteorder="big", signed=False)

        buy_sell_raw = udp_data[offset + 19:offset + 20]
        buy_sell_indicator = buy_sell_raw.decode('ascii', errors='ignore').strip()
        print(f"[DEBUG] Parsed Buy/Sell Indicator: {buy_sell_indicator} (raw: {buy_sell_raw.hex()})")

        shares_raw = udp_data[offset + 20:offset + 24]
        shares = int.from_bytes(shares_raw, byteorder="big", signed=False)
        print(f"[DEBUG] Parsed Shares: {shares} (raw bytes: {shares_raw.hex()})")

        stock_raw = udp_data[offset + 24:offset + 32]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        print(f"[DEBUG] Parsed Stock: {stock} (raw bytes: {stock_raw.hex()})")

        price_raw = udp_data[offset + 32:offset + 36]
        price = int.from_bytes(price_raw, byteorder="big", signed=False) / 10000.0
        print(f"[DEBUG] Parsed Price: {price} (raw bytes: {price_raw.hex()})")

        print(f"[DEBUG] Parsed A message - Stock: {stock}, Shares: {shares}, Price: {price}, Buy/Sell: {buy_sell_indicator}")
        return {
            "msg_type": "A",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number,
            "buy_sell_indicator": buy_sell_indicator,
            "shares": shares,
            "stock": stock,
            "price": price
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'A' message at offset {offset}: {e}")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

def order_executed_message(udp_data, offset):
    """
    Parse the 'E' (Order Executed Message) type according to the ITCH schema.
    """
    expected_length = 30  
    if not validate_message_length(udp_data, offset, expected_length, "E"):
        return None, len(udp_data)

    temp = struct.unpack_from(">HH6sQI8s", udp_data, offset)
    
    # Decode fields
    stock_locate = temp[0]
    tracking_number = temp[1]
    timestamp = struct.unpack(">Q", b"\x00\x00" + temp[2])[0] 
    order_ref_number = temp[3]
    executed_shares = temp[4]
    match_number = struct.unpack(">Q", temp[5])[0] 
    
    return {
        "msg_type": "E",
        "stock_locate": stock_locate,
        "tracking_number": tracking_number,
        "timestamp": timestamp,
        "order_ref_number": order_ref_number,
        "executed_shares": executed_shares,
        "match_number": match_number
    }, offset + expected_length

def cross_trade_message(udp_data, offset):
    """
    Parse the 'Q' (Cross Trade) message according to the ITCH protocol.
    """
    expected_length = 40  
    remaining_bytes = len(udp_data) - offset

    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for 'Q' message: needed {expected_length}, but only {remaining_bytes} available at offset {offset}.")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset + 1:offset + 3], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 3:offset + 5], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 5:offset + 11], byteorder="big", signed=False)

        shares_raw = udp_data[offset + 11:offset + 19]
        shares = int.from_bytes(shares_raw, byteorder="big", signed=False)
        print(f"[DEBUG] Parsed shares field: {shares} (raw: {shares_raw.hex()})")

        stock_raw = udp_data[offset + 19:offset + 27]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        print(f"[DEBUG] Parsed stock field: {stock} (raw: {stock_raw.hex()})")

        cross_price_raw = udp_data[offset + 27:offset + 31]
        cross_price = int.from_bytes(cross_price_raw, byteorder="big", signed=False) / 10000.0
        print(f"[DEBUG] Parsed cross price field: {cross_price} (raw: {cross_price_raw.hex()})")

        match_number_raw = udp_data[offset + 31:offset + 39]
        match_number = int.from_bytes(match_number_raw, byteorder="big", signed=False)
        print(f"[DEBUG] Parsed match number field: {match_number} (raw: {match_number_raw.hex()})")

        cross_type_raw = udp_data[offset + 39:offset + 40]
        cross_type = cross_type_raw.decode('ascii', errors='ignore').strip()
        print(f"[DEBUG] Parsed cross type field: {cross_type} (raw: {cross_type_raw.hex()})")

        print(f"[DEBUG] Parsed Q message - Stock: {stock}, Shares: {shares}, Cross Price: {cross_price}, Match Number: {match_number}, Cross Type: {cross_type}")

        return {
            "msg_type": "Q",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "shares": shares,
            "stock": stock,
            "cross_price": cross_price,
            "match_number": match_number,
            "cross_type": cross_type
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'Q' message at offset {offset}: {e}")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

def stock_trading_action_message(udp_data, offset):
    """
    Parse the 'H' (Stock Trading Action Message) according to the ITCH protocol.
    """
    expected_length = 25  
    remaining_bytes = len(udp_data) - offset

    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for 'H' message: needed {expected_length}, but only {remaining_bytes} available at offset {offset}.")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset + 1:offset + 3], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 3:offset + 5], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 5:offset + 11], byteorder="big", signed=False)

        stock_raw = udp_data[offset + 11:offset + 19]
        stock = stock_raw.decode('ascii', errors='ignore').strip()

        trading_state_raw = udp_data[offset + 19:offset + 20]
        trading_state = trading_state_raw.decode('ascii', errors='ignore').strip()

        reserved = udp_data[offset + 20:offset + 21]

        reason_raw = udp_data[offset + 21:offset + 25]
        reason = reason_raw.decode('ascii', errors='ignore').strip()

        print(f"[DEBUG] Parsed H message - Stock: {stock}, Trading State: {trading_state}, Reason: {reason}")

        return {
            "msg_type": "H",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "stock": stock,
            "trading_state": trading_state,
            "reserved": reserved.hex(),
            "reason": reason
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'H' message at offset {offset}: {e}")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

def non_cross_trade_message(udp_data, offset):
    """
    Parse the 'P' (Trade Message) according to the ITCH protocol.
    """
    expected_length = 43 
    remaining_bytes = len(udp_data) - offset

    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for 'P' message: needed {expected_length}, but only {remaining_bytes} available at offset {offset}.")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset + 1:offset + 3], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 3:offset + 5], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 5:offset + 11], byteorder="big", signed=False)

        order_ref_number = int.from_bytes(udp_data[offset + 11:offset + 19], byteorder="big", signed=False)
        shares = int.from_bytes(udp_data[offset + 19:offset + 23], byteorder="big", signed=False)

        stock_raw = udp_data[offset + 23:offset + 31]
        stock = stock_raw.decode('ascii', errors='ignore').strip()

        price_raw = udp_data[offset + 31:offset + 35]
        price = int.from_bytes(price_raw, byteorder="big", signed=False) / 10000.0

        match_number = int.from_bytes(udp_data[offset + 35:offset + 43], byteorder="big", signed=False)

        print(f"[DEBUG] Parsed P message - Stock: {stock}, Shares: {shares}, Price: {price}, Match Number: {match_number}")

        return {
            "msg_type": "P",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number,
            "shares": shares,
            "stock": stock,
            "price": price,
            "match_number": match_number
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'P' message at offset {offset}: {e}")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

def luld_auction_collar_message(udp_data, offset):
    """
    Parse the 'J' (Auction Update Message) according to the ITCH protocol.
    """
    expected_length = 49 
    remaining_bytes = len(udp_data) - offset

    if remaining_bytes < expected_length:
        print(f"[ERROR] Insufficient bytes for 'J' message: needed {expected_length}, but only {remaining_bytes} available at offset {offset}.")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset + 1:offset + 3], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 3:offset + 5], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 5:offset + 11], byteorder="big", signed=False)

        auction_type_raw = udp_data[offset + 11:offset + 12]
        auction_type = auction_type_raw.decode('ascii', errors='ignore').strip()

        stock_raw = udp_data[offset + 12:offset + 20]
        stock = stock_raw.decode('ascii', errors='ignore').strip()

        reference_price_raw = udp_data[offset + 20:offset + 24]
        reference_price = int.from_bytes(reference_price_raw, byteorder="big", signed=False) / 10000.0

        buy_shares = int.from_bytes(udp_data[offset + 24:offset + 32], byteorder="big", signed=False)
        sell_shares = int.from_bytes(udp_data[offset + 32:offset + 40], byteorder="big", signed=False)

        indicative_price_raw = udp_data[offset + 40:offset + 44]
        indicative_price = int.from_bytes(indicative_price_raw, byteorder="big", signed=False) / 10000.0

        auction_only_price_raw = udp_data[offset + 44:offset + 48]
        auction_only_price = int.from_bytes(auction_only_price_raw, byteorder="big", signed=False) / 10000.0

        print(f"[DEBUG] Parsed J message - Stock: {stock}, Auction Type: {auction_type}, Indicative Price: {indicative_price}")

        return {
            "msg_type": "J",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "auction_type": auction_type,
            "stock": stock,
            "reference_price": reference_price,
            "buy_shares": buy_shares,
            "sell_shares": sell_shares,
            "indicative_price": indicative_price,
            "auction_only_price": auction_only_price
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'J' message at offset {offset}: {e}")
        print(f"[DEBUG] Remaining payload (hex): {udp_data[offset:].hex()}")
        return None, len(udp_data)

def short_sale_price_test_message(udp_data, offset):
    """
    Parse the 'Y' (Short Sale Price Test Message) according to the ITCH protocol.
    """
    expected_length = 19 
    if not validate_message_length(udp_data, offset, expected_length, "Y"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)

        stock_raw = udp_data[offset + 10:offset + 18]
        stock = stock_raw.decode('ascii', errors='ignore').strip()

        action = udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "Y",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "stock": stock,
            "action": action
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'Y' message at offset {offset}: {e}")
        return None, len(udp_data)

def market_participation_position_message(udp_data, offset):
    """
    Parse the 'L' (Market Participation Position Message) according to the ITCH protocol.
    """
    expected_length = 25 
    if not validate_message_length(udp_data, offset, expected_length, "L"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)

        mpid_raw = udp_data[offset + 10:offset + 14]
        mpid = mpid_raw.decode('ascii', errors='ignore').strip()

        shares = int.from_bytes(udp_data[offset + 14:offset + 22], byteorder="big", signed=False)
        reserved = int.from_bytes(udp_data[offset + 22:offset + 25], byteorder="big", signed=False)

        return {
            "msg_type": "L",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "mpid": mpid,
            "shares": shares,
            "reserved": reserved
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'L' message at offset {offset}: {e}")
        return None, len(udp_data)

def mwcb_decline_level_message(udp_data, offset):
    """
    Parse the 'V' (MWCB Decline Level Message) according to the ITCH protocol.
    """
    expected_length = 34 
    if not validate_message_length(udp_data, offset, expected_length, "V"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)

        level_1 = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False) / 10**8
        level_2 = int.from_bytes(udp_data[offset + 18:offset + 26], byteorder="big", signed=False) / 10**8
        level_3 = int.from_bytes(udp_data[offset + 26:offset + 34], byteorder="big", signed=False) / 10**8

        return {
            "msg_type": "V",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "level_1": level_1,
            "level_2": level_2,
            "level_3": level_3
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'V' message at offset {offset}: {e}")
        return None, len(udp_data)

def mwcb_status_message(udp_data, offset):
    """
    Parse the 'W' (MWCB Status Message) according to the ITCH protocol.
    """
    expected_length = 11
    if not validate_message_length(udp_data, offset, expected_length, "W"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)

        breach_status_raw = udp_data[offset + 10:offset + 11]
        breach_status = breach_status_raw.decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "W",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "breach_status": breach_status
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'W' message at offset {offset}: {e}")
        return None, len(udp_data)

def ipo_quoting_period_update_message(udp_data, offset):
    """
    Parse the 'K' (IPO Quoting Period Update Message) according to the ITCH protocol.
    """
    expected_length = 28
    if not validate_message_length(udp_data, offset, expected_length, "K"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        stock_raw = udp_data[offset + 10:offset + 18]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        ipo_quotation_release_time = int.from_bytes(udp_data[offset + 18:offset + 22], byteorder="big", signed=False)
        ipo_quotation_release_qualifier = udp_data[offset + 22:offset + 23].decode('ascii', errors='ignore').strip()
        ipo_price = int.from_bytes(udp_data[offset + 23:offset + 27], byteorder="big", signed=False) / 10000.0

        return {
            "msg_type": "K",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "stock": stock,
            "ipo_quotation_release_time": ipo_quotation_release_time,
            "ipo_quotation_release_qualifier": ipo_quotation_release_qualifier,
            "ipo_price": ipo_price
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'K' message at offset {offset}: {e}")
        return None, len(udp_data)

def operational_halt_message(udp_data, offset):
    """
    Parse the 'h' (Operational Halt Message) according to the ITCH protocol.
    """
    expected_length = 20
    if not validate_message_length(udp_data, offset, expected_length, "h"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        stock_raw = udp_data[offset + 10:offset + 18]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        market_code = udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore').strip()
        operational_halt_action = udp_data[offset + 19:offset + 20].decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "h",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "stock": stock,
            "market_code": market_code,
            "operational_halt_action": operational_halt_action
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'h' message at offset {offset}: {e}")
        return None, len(udp_data)

def add_order_with_mpid_message(udp_data, offset):
    """
    Parse the 'F' (Add Order with MPID Message) according to the ITCH protocol.
    """
    expected_length = 40
    if not validate_message_length(udp_data, offset, expected_length, "F"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        order_ref_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)
        buy_sell_indicator = udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore').strip()
        shares = int.from_bytes(udp_data[offset + 19:offset + 23], byteorder="big", signed=False)
        stock_raw = udp_data[offset + 23:offset + 31]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        price = int.from_bytes(udp_data[offset + 31:offset + 35], byteorder="big", signed=False) / 10000.0
        attribution = udp_data[offset + 35:offset + 39].decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "F",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number,
            "buy_sell_indicator": buy_sell_indicator,
            "shares": shares,
            "stock": stock,
            "price": price,
            "attribution": attribution
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'F' message at offset {offset}: {e}")
        return None, len(udp_data)

def order_executed_with_price_message(udp_data, offset):
    """
    Parse the 'C' (Order Executed with Price Message) according to the ITCH protocol.
    """
    expected_length = 36
    if not validate_message_length(udp_data, offset, expected_length, "C"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        order_ref_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)
        executed_shares = int.from_bytes(udp_data[offset + 18:offset + 22], byteorder="big", signed=False)
        match_number = int.from_bytes(udp_data[offset + 22:offset + 30], byteorder="big", signed=False)
        printable = udp_data[offset + 30:offset + 31].decode('ascii', errors='ignore').strip()
        execution_price = int.from_bytes(udp_data[offset + 31:offset + 35], byteorder="big", signed=False) / 10000.0

        return {
            "msg_type": "C",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number,
            "executed_shares": executed_shares,
            "match_number": match_number,
            "printable": printable,
            "execution_price": execution_price
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'C' message at offset {offset}: {e}")
        return None, len(udp_data)

def order_cancel_message(udp_data, offset):
    """
    Parse the 'X' (Order Cancel Message) according to the ITCH protocol.
    """
    expected_length = 23
    if not validate_message_length(udp_data, offset, expected_length, "X"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        order_ref_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)
        canceled_shares = int.from_bytes(udp_data[offset + 18:offset + 22], byteorder="big", signed=False)

        return {
            "msg_type": "X",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number,
            "canceled_shares": canceled_shares
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'X' message at offset {offset}: {e}")
        return None, len(udp_data)

def order_delete_message(udp_data, offset):
    """
    Parse the 'D' (Order Delete Message) according to the ITCH protocol.
    """
    expected_length = 19
    if not validate_message_length(udp_data, offset, expected_length, "D"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        order_ref_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)

        return {
            "msg_type": "D",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "order_ref_number": order_ref_number
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'D' message at offset {offset}: {e}")
        return None, len(udp_data)

def order_replace_message(udp_data, offset):
    """
    Parse the 'U' (Order Replace Message) according to the ITCH protocol.
    """
    expected_length = 35
    if not validate_message_length(udp_data, offset, expected_length, "U"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        original_order_ref_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)
        new_order_ref_number = int.from_bytes(udp_data[offset + 18:offset + 26], byteorder="big", signed=False)
        shares = int.from_bytes(udp_data[offset + 26:offset + 30], byteorder="big", signed=False)
        price = int.from_bytes(udp_data[offset + 30:offset + 34], byteorder="big", signed=False) / 10000.0

        return {
            "msg_type": "U",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "original_order_ref_number": original_order_ref_number,
            "new_order_ref_number": new_order_ref_number,
            "shares": shares,
            "price": price
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'U' message at offset {offset}: {e}")
        return None, len(udp_data)

def broken_trade_message(udp_data, offset):
    """
    Parse the 'B' (Broken Trade Message) according to the ITCH protocol.
    """
    expected_length = 19
    if not validate_message_length(udp_data, offset, expected_length, "B"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        match_number = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)

        return {
            "msg_type": "B",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "match_number": match_number
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'B' message at offset {offset}: {e}")
        return None, len(udp_data)

def net_order_imbalance_indicator_message(udp_data, offset):
    """
    Parse the 'I' (Net Order Imbalance Indicator Message) according to the ITCH protocol.
    """
    expected_length = 50
    if not validate_message_length(udp_data, offset, expected_length, "I"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        paired_shares = int.from_bytes(udp_data[offset + 10:offset + 18], byteorder="big", signed=False)
        imbalance_shares = int.from_bytes(udp_data[offset + 18:offset + 26], byteorder="big", signed=False)
        imbalance_direction = udp_data[offset + 26:offset + 27].decode('ascii', errors='ignore').strip()
        stock_raw = udp_data[offset + 27:offset + 35]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        far_price = int.from_bytes(udp_data[offset + 35:offset + 39], byteorder="big", signed=False) / 10000.0
        near_price = int.from_bytes(udp_data[offset + 39:offset + 43], byteorder="big", signed=False) / 10000.0
        current_reference_price = int.from_bytes(udp_data[offset + 43:offset + 47], byteorder="big", signed=False) / 10000.0
        cross_type = udp_data[offset + 47:offset + 48].decode('ascii', errors='ignore').strip()
        price_variation_indicator = udp_data[offset + 48:offset + 49].decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "I",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "paired_shares": paired_shares,
            "imbalance_shares": imbalance_shares,
            "imbalance_direction": imbalance_direction,
            "stock": stock,
            "far_price": far_price,
            "near_price": near_price,
            "current_reference_price": current_reference_price,
            "cross_type": cross_type,
            "price_variation_indicator": price_variation_indicator
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'I' message at offset {offset}: {e}")
        return None, len(udp_data)

def retail_price_improvement_indicator_message(udp_data, offset):
    """
    Parse the 'O' (Retail Price Improvement Indicator Message) according to the ITCH protocol.
    """
    expected_length = 20
    if not validate_message_length(udp_data, offset, expected_length, "O"):
        return None, len(udp_data)

    try:
        stock_locate = int.from_bytes(udp_data[offset:offset + 2], byteorder="big", signed=False)
        tracking_number = int.from_bytes(udp_data[offset + 2:offset + 4], byteorder="big", signed=False)
        timestamp = int.from_bytes(udp_data[offset + 4:offset + 10], byteorder="big", signed=False)
        stock_raw = udp_data[offset + 10:offset + 18]
        stock = stock_raw.decode('ascii', errors='ignore').strip()
        interest_flag = udp_data[offset + 18:offset + 19].decode('ascii', errors='ignore').strip()

        return {
            "msg_type": "O",
            "stock_locate": stock_locate,
            "tracking_number": tracking_number,
            "timestamp": timestamp,
            "stock": stock,
            "interest_flag": interest_flag
        }, offset + expected_length

    except Exception as e:
        print(f"[ERROR] Parsing failed for 'O' message at offset {offset}: {e}")
        return None, len(udp_data)
