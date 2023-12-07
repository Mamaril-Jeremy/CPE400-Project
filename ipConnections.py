from scapy.all import rdpcap, wrpcap

def clean_and_save_capture(input_file, output_file):
    packets = rdpcap(input_file)

    ip_packets = [pkt for pkt in packets if pkt.haslayer('IP')]

    new_capture = ip_packets

    # Step 4: Save the new capture to another file
    wrpcap(output_file, new_capture)

# Replace 'your_capture_file.pcap' with the actual input file name
input_file = 'clash_data.pcapng'

# Replace 'cleaned_capture.pcap' with the desired output file name
output_file = 'ip_capture.pcapng'

# Call the function to clean and save the capture
clean_and_save_capture(input_file, output_file)