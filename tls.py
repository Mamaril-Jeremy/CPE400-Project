from scapy.all import rdpcap, wrpcap

def extract_tls_information(input_file, output_file):
    # Step 1: Read the Wireshark capture
    packets = rdpcap(input_file)

    # Step 2: Filter packets (e.g., only TCP packets)
    tcp_packets = [pkt for pkt in packets if pkt.haslayer('TCP')]

    # Step 3: Filter TCP packets with TLS records
    tls_packets = [pkt for pkt in tcp_packets if pkt.haslayer('TLS')]

    # Step 4: Save the TLS packets to another file
    wrpcap(output_file, tls_packets)

# Replace 'your_capture_file.pcap' with the actual input file name
input_file = 'clash_data.pcapng'

# Replace 'tls_capture.pcapng' with the desired output file name
output_file = 'tls_capture.pcapng'

# Call the function to extract TLS information and save the capture
extract_tls_information(input_file, output_file)
