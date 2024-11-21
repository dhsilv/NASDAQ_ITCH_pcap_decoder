import dpkt

pcap_file = '/Users/rishimulchandani/local_nasdaq_decoder/rishi-pcap-decoder/ny4-xnas-tvitch-a-20230822T133000.pcap' 

# Open the PCAP file
with open(pcap_file, 'rb') as f:
    # Use dpkt's pcap.Reader to read the PCAP file
    pcap_reader = dpkt.pcap.Reader(f)    
    # Initialize a counter to limit to the first 1000 packets
    packet_count = 0
    max_packets = 1000
    
    # Iterate through each packet in the PCAP file
    for timestamp, packet in pcap_reader:
        if packet_count >= max_packets:
            break  # Stop after 1000 packets

        # Increment the packet counter
        packet_count += 1
        
        # Print timestamp and raw packet (optional)
        print(f"Packet #{packet_count} Timestamp: {timestamp}")
        print(f"Raw Packet: {repr(packet)}")

        # # Optionally, parse the Ethernet frame
        # eth = dpkt.ethernet.Ethernet(packet)
        # print(f"Ethernet Frame: {eth}")
        
    print(f"Processed {packet_count} packets.")
