import pyshark
from collections import Counter

def analyze_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    encryption_standards = Counter()

    for packet in capture:
        # Check if the packet has a Transport Layer Security (TLS) layer
        if 'TLS' in packet:
            # Extract encryption information from the TLS layer
            encryption_standard = packet.tls.get('tls.record.content_type', 'Unknown')
            encryption_standards[encryption_standard] += 1

    # Print the summary of encryption standards
    print("Summary of Encryption Standards:")
    for standard, count in encryption_standards.items():
        print(f"{standard}: {count} packets")

if __name__ == "__main__":
    pcap_file = "tcp_capture.pcapng"  # Replace with the path to your pcapng file
    analyze_pcap(pcap_file)
