#Jeremy Mamaril and Brandon Yu

import pyshark

def analyze_packet(packet):
    # Add your analysis logic here
    # Filters out packets that have resets and duplicate ACKs
    if 'TCP' in packet and ('RST' in packet['TCP'].flags or 'DUP ACK' in packet['TCP'].flags):
        return
    print(packet)

def main():
    capture_file = 'clash_data.pcapng'
    packets = pyshark.FileCapture(capture_file, display_filter="tcp")
    analyze_packet(packets[0])
    # try:
    #     packets = pyshark.FileCapture(capture_file, display_filter='your_display_filter')
       
    #     for packet in packets:
    #         analyze_packet(packet)
    
    # except FileNotFoundError:
    #     print(f"Error: File '{capture_file}' not found.")
    # except Exception as e:
    #     print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
