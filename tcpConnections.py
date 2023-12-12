# TCP Connection Script

from scapy.all import rdpcap, TCP, IP, IPv6
from tabulate import tabulate

def analyze_tcp_connections(pcap_file):
    packets = rdpcap(pcap_file)
    tcp_connections = {}
    connection_count = 0

    for packet in packets:
        if TCP in packet:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                continue

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            connection_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"

            if connection_key not in tcp_connections:
                tcp_connections[connection_key] = {'seq_nums': [], 'ack_nums': []}
                connection_count += 1

                if connection_count > 2:
                    break

            tcp_connections[connection_key]['seq_nums'].append(packet[TCP].seq)
            tcp_connections[connection_key]['ack_nums'].append(packet[TCP].ack)

    table_data = []
    for connection, values in tcp_connections.items():
        table_data.append([connection,
                           ', '.join(map(str, values['seq_nums'])),
                           ', '.join(map(str, values['ack_nums']))])

    for item in table_data:
        print(f"Connection: {item[0]}")
        print(f"Sequence Numbers: {item[1]}")
        print(f"Acknowledgment Numbers: {item[2]}")
        print()

analyze_tcp_connections('clash_data.pcapng')
