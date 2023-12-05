import pyshark

def analyze_and_save_packet(packet, output_cap):
    if 'TCP' in packet and ('RST' in packet['TCP'].flags or 'DUP ACK' in packet['TCP'].flags):
        return
    output_cap.write(packet)

def main():
    input_capture_file = 'clash_data.pcapng'
    output_capture_file = 'filtered_data.pcapng'

    try:
        # Open the input capture file
        input_packets = pyshark.FileCapture(input_capture_file, display_filter="tcp")
        
        # Open a new capture file for writing filtered packets
        output_packets = pyshark.FileCapture(output_capture_file, mode=pyshark.OutputWriter, output_file=output_capture_file, override=True)

        # Analyze and save each packet
        for packet in input_packets:
            analyze_and_save_packet(packet, output_packets)
    
    except FileNotFoundError:
        print(f"Error: File '{input_capture_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
