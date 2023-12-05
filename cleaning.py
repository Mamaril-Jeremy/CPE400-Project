from scapy.all import rdpcap, wrpcap

def clean_and_save_capture(input_file, output_file):
    # Step 1: Read the Wireshark capture
    packets = rdpcap(input_file)

    # Step 2: Filter packets (e.g., only TCP packets)
    tcp_packets = [pkt for pkt in packets if pkt.haslayer('TCP')]

    # Step 3: Create a new Scapy PacketList
    new_capture = tcp_packets

    # Step 4: Save the new capture to another file
    wrpcap(output_file, new_capture)

# Replace 'your_capture_file.pcap' with the actual input file name
input_file = 'clash_data.pcapng'

# Replace 'cleaned_capture.pcap' with the desired output file name
output_file = 'cleaned_capture.pcapng'

# Call the function to clean and save the capture
clean_and_save_capture(input_file, output_file)
