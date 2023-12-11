import pyshark
from collections import Counter
from tabulate import tabulate

def get_tls_content_type_label(content_type):
    # Mapping of TLS content type numeric values to labels
    content_type_labels = {
        '20': 'ChangeCipherSpec',
        '21': 'Alert',
        '22': 'Handshake',
        '23': 'ApplicationData',
        '24': 'Heartbeat',
    }
    return content_type_labels.get(content_type, 'Unknown')

def analyze_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    encryption_standards = Counter()

    for packet in capture:
        #Check if the packet has a Transport Layer Security (TLS) layer
        if 'TCP' in packet and ('RST' in packet['TCP'].flags or 'DUP ACK' in packet['TCP'].flags):
            continue
        if 'TLS' in packet:
            # Extract encryption information from the TLS layer
            encryption_standard = packet.tls.get('tls.record.content_type', 'Unknown')
            encryption_standards[get_tls_content_type_label(encryption_standard)] += 1

    # Prepare the results for tabulate
    headers = ["Encryption Standard", "Packets"]
    data = [(standard, count) for standard, count in encryption_standards.items()]

    # Print the tabulated summary of encryption standards
    print(tabulate(data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    pcap_file = "clash_data.pcapng"  # Replace with the path to your pcapng file
    analyze_pcap(pcap_file)
