from scapy.all import rdpcap, IP, TCP
from tabulate import tabulate

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)

    results = []

    for packet in packets:
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Check for SYN (connection establishment)
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                results.append(["SYN", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"])

            # Check for ACK to complete three-way handshake
            elif packet[TCP].flags.S and packet[TCP].flags.A:
                results.append(["SYN-ACK", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"])

            # Check for FIN (connection termination)
            elif packet[TCP].flags.F and packet[TCP].flags.A:
                results.append(["FIN-ACK", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"])

            # Check for ACK to complete connection termination
            elif packet[TCP].flags.A and not packet[TCP].flags.S and not packet[TCP].flags.F:
                results.append(["ACK", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"])

            # Add additional checks for anomalies here
            # Example: Check for unexpected flags, payload inspection, etc.

    # Print the results as a table
    headers = ["Event", "Details"]
    print(tabulate(results, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    pcap_file = "your_file.pcapng"  # Replace with the path to your pcapng file
    analyze_packets(pcap_file)
