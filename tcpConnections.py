from scapy.all import rdpcap, IP, IPv6, TCP
from tabulate import tabulate

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)

    active_connections = set()
    opened_connections = set()
    closed_connections = set()

    for packet in packets:
        print(f"Packet summary: {packet.summary()}")

        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            connection = (src_ip, src_port, dst_ip, dst_port)

            print(f"TCP Flags: {packet[TCP].flags}")
            print(f"Connection: {connection}")

            # Check for SYN (connection establishment)
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                opened_connections.add(connection)
                print("SYN - Connection Opened")
            elif packet[TCP].flags.S and packet[TCP].flags.A:
                opened_connections.discard(connection)
                active_connections.add(connection)
                print("SYN-ACK - Connection Established")

            # Check for FIN-ACK (connection termination)
            elif packet[TCP].flags.F and packet[TCP].flags.A:
                active_connections.discard(connection)
                closed_connections.add(connection)
                print("FIN-ACK - Connection Closed")

            # Check for ACK to complete connection termination
            elif packet[TCP].flags.A and not packet[TCP].flags.S and not packet[TCP].flags.F:
                closed_connections.discard(connection)
                print("ACK - Connection Fully Closed")

        elif IPv6 in packet and TCP in packet:
            # Handle IPv6 packets
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            connection = (src_ip, src_port, dst_ip, dst_port)

            print(f"IPv6 TCP Flags: {packet[TCP].flags}")
            print(f"IPv6 Connection: {connection}")

            # Add logic for IPv6 packets as needed

    # Print the results as a table
    headers = ["Event", "Details"]
    results = [
        ["Connections Opened", len(opened_connections)],
        ["Connections Closed", len(closed_connections)],
        ["Active Connections", len(active_connections)],
    ]
    print(tabulate(results, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    pcap_file = "cleaned_capture.pcapng"  # Replace with the path to your pcapng file
    analyze_packets(pcap_file)
