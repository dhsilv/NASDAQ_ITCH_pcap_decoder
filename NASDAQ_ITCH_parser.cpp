#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <map>

using namespace std;

#pragma pack(push, 1)
struct PcapFileHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

class NASDAQITCHParser {
private:
    string input_filepath;
    string output_filepath;
    ifstream input_file;
    ofstream output_trade_file;
    ofstream output_order_file;

    struct OrderInfo {
        double timestamp;
        uint64_t reference;
        char buy_sell_indicator;
        uint32_t shares;
        string stock;
        uint32_t price;
    };

    struct ExecuteInfo {
        double timestamp;
        uint64_t reference;
        uint32_t executed_shares;
        string stock;
        uint32_t executed_price;
        uint64_t match_number;
        bool printable;
    };

    unordered_map<uint64_t, OrderInfo> orders;
    unordered_map<uint64_t, ExecuteInfo> executes;

public:
    NASDAQITCHParser(const string& input, const string& output)
        : input_filepath(input), output_filepath(output) {}

    int parse() {
        input_file.open(input_filepath, ios::binary);
        if (!input_file.is_open()) {
            cerr << "[ERROR] Unable to open input file: " << input_filepath << endl;
            return -1;
        }
        cout << "[INFO] Opened input file: " << input_filepath << endl;

        output_trade_file.open(output_filepath + "_trades.csv");
        if (!output_trade_file.is_open()) {
            cerr << "[ERROR] Unable to open output trade file: " << output_filepath + "_trades.csv" << endl;
            return -1;
        }
        cout << "[INFO] Opened output trade file: " << output_filepath + "_trades.csv" << endl;

        output_order_file.open(output_filepath + "_orders.csv");
        if (!output_order_file.is_open()) {
            cerr << "[ERROR] Unable to open output order file: " << output_filepath + "_orders.csv" << endl;
            return -1;
        }
        cout << "[INFO] Opened output order file: " << output_filepath + "_orders.csv" << endl;

        output_trade_file << "Timestamp,Stock,ExecutedShares,Price,MatchNumber\n";
        output_order_file << "Timestamp,Stock,OrderID,Shares,Price,Action\n";

        parse_pcap_file();

        output_trade_file.flush();
        output_trade_file.close();
        output_order_file.flush();
        output_order_file.close();

        cout << "[INFO] Parsing complete. Data saved to " << output_filepath << "_trades.csv and " << output_filepath << "_orders.csv" << endl;
        return 0;
    }

    void parse_pcap_file() {
        // Read the PCAP file header
        PcapFileHeader file_header;
        input_file.read(reinterpret_cast<char*>(&file_header), sizeof(PcapFileHeader));
        if (input_file.gcount() != sizeof(PcapFileHeader)) {
            cerr << "[ERROR] Failed to read PCAP file header." << endl;
            return;
        }

        while (input_file) {
            // Read each packet header
            PcapPacketHeader packet_header;
            input_file.read(reinterpret_cast<char*>(&packet_header), sizeof(PcapPacketHeader));
            if (input_file.gcount() != sizeof(PcapPacketHeader)) {
                cerr << "[DEBUG] Reached end of file or incomplete packet header." << endl;
                break;
            }

            // Read the packet data
            vector<uint8_t> packet_data(packet_header.incl_len);
            input_file.read(reinterpret_cast<char*>(packet_data.data()), packet_header.incl_len);
            if (input_file.gcount() != packet_header.incl_len) {
                cerr << "[ERROR] Incomplete packet data." << endl;
                break;
            }

            // Parse ITCH data within this packet
            parse_itch_data(packet_data);
        }
    }

    void parse_itch_data(const vector<uint8_t>& data) {
        size_t offset = 0;
        while (offset < data.size()) {
            // Read one byte for the message type
            char message_type_char = data[offset++];
            uint8_t message_type = static_cast<uint8_t>(message_type_char);
            size_t message_length = get_itch_message_length(static_cast<char>(message_type));

            if (message_length == 0 || offset + message_length - 1 > data.size()) {
                cerr << "[WARN] Unknown or unhandled message type: " << message_type_char << " (ASCII: " << int(message_type_char) << ")" << endl;
                continue;
            }

            vector<uint8_t> message_data(data.begin() + offset, data.begin() + offset + message_length - 1);
            offset += message_length - 1;

            parse_itch_message(static_cast<char>(message_type), message_data);
        }
    }

    size_t get_itch_message_length(char message_type) {
        switch (message_type) {
        case 'S': return 11;
        case 'R': return 39;
        case 'H': return 25;
        case 'Y': return 20;
        case 'L': return 25;
        case 'V': return 34;
        case 'W': return 11;
        case 'K': return 28;
        case 'A': return 36;
        case 'F': return 40;
        case 'E': return 30;
        case 'C': return 35;
        case 'X': return 22;
        case 'D': return 18;
        case 'U': return 34;
        case 'P': return 44;
        case 'Q': return 40;
        case 'B': return 19;
        case 'I': return 50;
        case 'N': return 20;
        default: return 0;
        }
    }

    void parse_itch_message(char message_type, const vector<uint8_t>& message_data) {
        if (message_data.size() + 1 != get_itch_message_length(message_type)) {
            cerr << "[ERROR] Incorrect message length for type " << message_type << ". Expected "
                << get_itch_message_length(message_type) << ", got " << message_data.size() + 1 << endl;
            return;
        }

        switch (message_type) {
        case 'S': parse_system_event_message(message_data); break;
        case 'R': parse_stock_directory_message(message_data); break;
        case 'H': parse_stock_trading_action_message(message_data); break;
        case 'A': parse_add_order_no_mpid(message_data); break;
        case 'F': parse_add_order_with_mpid(message_data); break;
        case 'E': parse_order_executed_message(message_data); break;
        case 'C': parse_order_executed_with_price_message(message_data); break;
        case 'X': parse_order_cancel_message(message_data); break;
        case 'D': parse_order_delete_message(message_data); break;
        case 'U': parse_order_replace_message(message_data); break;
        case 'P': parse_non_cross_trade_message(message_data); break;
        case 'Q': parse_cross_trade_message(message_data); break;
        case 'B': parse_broken_trade_message(message_data); break;
        default:
            cout << "[DEBUG] Unhandled message type: " << message_type << endl;
            break;
        }
    }


    // Parsing functions for different ITCH messages
    void parse_system_event_message(const vector<uint8_t>& data) {
        if (data.size() < 10) {
            cerr << "[ERROR] Invalid System Event message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        char event_code = (char)data[10];

        double system_event_time = (double)timestamp / 1e9; // Convert nanoseconds to seconds
        // Debugging output
        cout << "[DEBUG] System Event Message: Event Code = " << event_code
            << ", Timestamp = " << system_event_time << endl;
    }

    void parse_stock_directory_message(const vector<uint8_t>& data) {
        if (data.size() < 38) {
            cerr << "[ERROR] Invalid Stock Directory message size: " << data.size() << " bytes." << endl;
            return;
        }

        char stock[9] = { 0 };
        memcpy(stock, &data[10], 8);
        // Debugging output
        cout << "[DEBUG] Stock Directory Message: Stock = " << stock << endl;
    }

    void parse_stock_trading_action_message(const vector<uint8_t>& data) {
        if (data.size() < 24) {
            cerr << "[ERROR] Invalid Stock Trading Action message size: " << data.size() << " bytes." << endl;
            return;
        }

        char stock[9] = { 0 };
        memcpy(stock, &data[10], 8);
        char trading_state = (char)data[18];
        // Debugging output
        cout << "[DEBUG] Stock Trading Action Message: Stock = " << stock
            << ", Trading State = " << trading_state << endl;
    }

    void parse_add_order_no_mpid(const vector<uint8_t>& data) {
        if (data.size() < 35) {
            cerr << "[ERROR] Invalid Add Order (No MPID) message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        char buy_sell = (char)data[18];
        uint32_t shares = (data[19] << 24) | (data[20] << 16) | (data[21] << 8) | data[22];
        char stock[9] = { 0 };
        memcpy(stock, &data[23], 8);
        uint32_t price = (data[31] << 24) | (data[32] << 16) | (data[33] << 8) | data[34];

        orders[ref_num] = { message_time, ref_num, buy_sell, shares, string(stock), price };

        // Write to orders CSV immediately
        output_order_file << message_time << "," << stock << "," << ref_num << "," << shares << "," << price << ",Add\n";
        output_order_file.flush();

        // Debug output
        cout << "[DEBUG] Add Order (No MPID): Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Stock = " << stock
            << ", Shares = " << shares << ", Price = " << price
            << ", Buy/Sell = " << buy_sell << endl;
    }

    void parse_add_order_with_mpid(const vector<uint8_t>& data) {
        if (data.size() < 39) {
            cerr << "[ERROR] Invalid Add Order (with MPID) message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        char buy_sell = (char)data[18];
        uint32_t shares = (data[19] << 24) | (data[20] << 16) | (data[21] << 8) | data[22];
        char stock[9] = { 0 };
        memcpy(stock, &data[23], 8);
        uint32_t price = (data[31] << 24) | (data[32] << 16) | (data[33] << 8) | data[34];
        // MPID field is data[35]-[38], not used in this example

        orders[ref_num] = { message_time, ref_num, buy_sell, shares, string(stock), price };

        // Write to orders CSV immediately
        output_order_file << message_time << "," << stock << "," << ref_num << "," << shares << "," << price << ",Add\n";
        output_order_file.flush();

        // Debug output
        cout << "[DEBUG] Add Order (with MPID): Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Stock = " << stock
            << ", Shares = " << shares << ", Price = " << price
            << ", Buy/Sell = " << buy_sell << endl;
    }

    void parse_order_executed_message(const vector<uint8_t>& data) {
        if (data.size() < 29) {
            cerr << "[ERROR] Invalid Order Executed message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        uint32_t executed_shares = (data[18] << 24) | (data[19] << 16) | (data[20] << 8) | data[21];
        uint64_t match_number = ((uint64_t)data[22] << 56) | ((uint64_t)data[23] << 48) |
            ((uint64_t)data[24] << 40) | ((uint64_t)data[25] << 32) |
            ((uint64_t)data[26] << 24) | ((uint64_t)data[27] << 16) |
            ((uint64_t)data[28] << 8) | (uint64_t)data[29];

        if (orders.find(ref_num) != orders.end()) {
            const auto& order_info = orders[ref_num];
            executes[match_number] = {
                message_time, ref_num, executed_shares, order_info.stock, order_info.price, match_number, true
            };

            // Write to trades CSV immediately
            output_trade_file << message_time << "," << order_info.stock << "," << executed_shares << "," << order_info.price << "," << match_number << "\n";
            output_trade_file.flush();
        }
        else {
            cerr << "[WARN] Executed order reference number not found: " << ref_num << endl;
        }

        // Debug output
        cout << "[DEBUG] Order Executed: Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Executed Shares = " << executed_shares
            << ", Match Number = " << match_number << endl;
    }

    void parse_order_executed_with_price_message(const vector<uint8_t>& data) {
        if (data.size() < 34) {
            cerr << "[ERROR] Invalid Order Executed with Price message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        uint32_t executed_shares = (data[18] << 24) | (data[19] << 16) | (data[20] << 8) | data[21];
        uint64_t match_number = ((uint64_t)data[22] << 56) | ((uint64_t)data[23] << 48) |
            ((uint64_t)data[24] << 40) | ((uint64_t)data[25] << 32) |
            ((uint64_t)data[26] << 24) | ((uint64_t)data[27] << 16) |
            ((uint64_t)data[28] << 8) | (uint64_t)data[29];
        char printable_flag = (char)data[30];
        uint32_t executed_price = (data[31] << 24) | (data[32] << 16) | (data[33] << 8) | data[34];

        bool printable = (printable_flag == 'Y');

        if (orders.find(ref_num) != orders.end()) {
            const auto& order_info = orders[ref_num];
            executes[match_number] = {
                message_time, ref_num, executed_shares, order_info.stock, executed_price, match_number, printable
            };

            // Write to trades CSV immediately
            output_trade_file << message_time << "," << order_info.stock << "," << executed_shares << "," << executed_price << "," << match_number << "\n";
            output_trade_file.flush();
        }
        else {
            cerr << "[WARN] Executed order (with price) reference number not found: " << ref_num << endl;
        }

        // Debug output
        cout << "[DEBUG] Order Executed with Price: Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Executed Shares = " << executed_shares
            << ", Match Number = " << match_number << ", Executed Price = " << executed_price
            << ", Printable = " << printable << endl;
    }

    void parse_order_cancel_message(const vector<uint8_t>& data) {
        if (data.size() < 21) {
            cerr << "[ERROR] Invalid Order Cancel message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        uint32_t cancelled_shares = (data[18] << 24) | (data[19] << 16) | (data[20] << 8) | data[21];

        if (orders.find(ref_num) != orders.end()) {
            auto& order_info = orders[ref_num];
            if (order_info.shares >= cancelled_shares) {
                order_info.shares -= cancelled_shares;
            }
            else {
                cerr << "[WARN] Cancelled shares exceed existing order shares for order " << ref_num << endl;
            }
        }
        else {
            cerr << "[WARN] Attempted to cancel an unknown order reference: " << ref_num << endl;
        }

        // Debug output
        cout << "[DEBUG] Order Cancel: Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Cancelled Shares = " << cancelled_shares << endl;
    }

    void parse_order_delete_message(const vector<uint8_t>& data) {
        if (data.size() < 17) {
            cerr << "[ERROR] Invalid Order Delete message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];

        // If the order is found, remove it or mark it as deleted.
        if (orders.find(ref_num) != orders.end()) {
            orders.erase(ref_num);
        }
        else {
            cerr << "[WARN] Attempted to delete an unknown order reference: " << ref_num << endl;
        }

        // Debug output
        cout << "[DEBUG] Order Deleted: Timestamp = " << message_time
            << ", Order ID = " << ref_num << endl;
    }

    void parse_order_replace_message(const vector<uint8_t>& data) {
        if (data.size() < 33) {
            cerr << "[ERROR] Invalid Order Replace message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t old_ref = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        uint64_t new_ref = ((uint64_t)data[18] << 56) | ((uint64_t)data[19] << 48) |
            ((uint64_t)data[20] << 40) | ((uint64_t)data[21] << 32) |
            ((uint64_t)data[22] << 24) | ((uint64_t)data[23] << 16) |
            ((uint64_t)data[24] << 8) | (uint64_t)data[25];
        uint32_t shares = (data[26] << 24) | (data[27] << 16) | (data[28] << 8) | data[29];
        uint32_t price = (data[30] << 24) | (data[31] << 16) | (data[32] << 8) | data[33];

        if (orders.find(old_ref) != orders.end()) {
            OrderInfo old_order = orders[old_ref];
            orders.erase(old_ref);
            orders[new_ref] = { message_time, new_ref, old_order.buy_sell_indicator, shares, old_order.stock, price };

            // Write updated order data to orders CSV immediately
            output_order_file << message_time << "," << old_order.stock << "," << new_ref << "," << shares << "," << price << ",Replace\n";
            output_order_file.flush();

            // Debug output
            cout << "[DEBUG] Order Replace: Timestamp = " << message_time
                << ", Old Order ID = " << old_ref << ", New Order ID = " << new_ref
                << ", Shares = " << shares << ", Price = " << price << endl;
        }
        else {
            cerr << "[WARN] Attempted to replace an unknown order reference: " << old_ref << endl;
        }
    }

    void parse_non_cross_trade_message(const vector<uint8_t>& data) {
        if (data.size() < 43) {
            cerr << "[ERROR] Invalid Non-Cross Trade message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t ref_num = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];
        char buy_sell = (char)data[18];
        uint32_t shares = (data[19] << 24) | (data[20] << 16) | (data[21] << 8) | data[22];
        char stock[9] = { 0 };
        memcpy(stock, &data[23], 8);
        uint32_t price = (data[31] << 24) | (data[32] << 16) | (data[33] << 8) | data[34];
        uint64_t match_number = ((uint64_t)data[35] << 56) | ((uint64_t)data[36] << 48) |
            ((uint64_t)data[37] << 40) | ((uint64_t)data[38] << 32) |
            ((uint64_t)data[39] << 24) | ((uint64_t)data[40] << 16) |
            ((uint64_t)data[41] << 8) | (uint64_t)data[42];

        // This is a trade
        executes[match_number] = { message_time, ref_num, shares, string(stock), price, match_number, true };

        // Write to trades CSV immediately
        output_trade_file << message_time << "," << stock << "," << shares << "," << price << "," << match_number << "\n";
        output_trade_file.flush();

        // Debug output
        cout << "[DEBUG] Non-Cross Trade: Timestamp = " << message_time
            << ", Order ID = " << ref_num << ", Stock = " << stock
            << ", Shares = " << shares << ", Price = " << price
            << ", Match Number = " << match_number
            << ", Buy/Sell = " << buy_sell << endl;
    }

    void parse_cross_trade_message(const vector<uint8_t>& data) {
        if (data.size() < 39) {
            cerr << "[ERROR] Invalid Cross Trade message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        char stock[9] = { 0 };
        memcpy(stock, &data[10], 8);
        uint64_t match_number = ((uint64_t)data[34] << 56) | ((uint64_t)data[35] << 48) |
            ((uint64_t)data[36] << 40) | ((uint64_t)data[37] << 32) |
            ((uint64_t)data[38] << 24) | ((uint64_t)data[39] << 16) |
            ((uint64_t)data[40] << 8) | (uint64_t)data[41];
        uint32_t cross_price = (data[30] << 24) | (data[31] << 16) | (data[32] << 8) | data[33];
        uint64_t shares = ((uint64_t)data[22] << 56) | ((uint64_t)data[23] << 48) |
            ((uint64_t)data[24] << 40) | ((uint64_t)data[25] << 32) |
            ((uint64_t)data[26] << 24) | ((uint64_t)data[27] << 16) |
            ((uint64_t)data[28] << 8) | (uint64_t)data[29];

        // This message indicates a cross trade
        // Debug output
        cout << "[DEBUG] Cross Trade: Timestamp = " << message_time
            << ", Stock = " << stock << ", Shares = " << shares
            << ", Cross Price = " << cross_price
            << ", Match Number = " << match_number << endl;
    }

    void parse_broken_trade_message(const vector<uint8_t>& data) {
        if (data.size() < 18) {
            cerr << "[ERROR] Invalid Broken Trade message size: " << data.size() << " bytes." << endl;
            return;
        }

        uint64_t timestamp = ((uint64_t)data[4] << 40) | ((uint64_t)data[5] << 32) |
            ((uint64_t)data[6] << 24) | ((uint64_t)data[7] << 16) |
            ((uint64_t)data[8] << 8) | (uint64_t)data[9];
        double message_time = (double)timestamp / 1e9;
        uint64_t match_number = ((uint64_t)data[10] << 56) | ((uint64_t)data[11] << 48) |
            ((uint64_t)data[12] << 40) | ((uint64_t)data[13] << 32) |
            ((uint64_t)data[14] << 24) | ((uint64_t)data[15] << 16) |
            ((uint64_t)data[16] << 8) | (uint64_t)data[17];

        // If the trade is found, mark it as broken
        if (executes.find(match_number) != executes.end()) {
            executes.erase(match_number);
        }
        else {
            cerr << "[WARN] Broken trade referenced an unknown match number: " << match_number << endl;
        }

        // Debug output
        cout << "[DEBUG] Broken Trade: Timestamp = " << message_time
            << ", Match Number = " << match_number << endl;
    }
};
int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "[ERROR] Usage: " << argv[0] << " <input_itch_file> <output_file_prefix>" << endl;
        return 1;
    }

    string input_filepath = argv[1];
    string output_filepath = argv[2];

    cout << "[INFO] Input file: " << input_filepath << endl;
    cout << "[INFO] Output file prefix: " << output_filepath << endl;

    NASDAQITCHParser parser(input_filepath, output_filepath);
    int result = parser.parse();

    return result;
}








