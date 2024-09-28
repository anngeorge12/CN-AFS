from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from collections import defaultdict

# Load the PCAP file
pcap_file_path = r"C:\Users\Yexus\Documents\captured.pcap"  # Update with your actual path
packets = rdpcap(pcap_file_path)

# Dictionary to store flow statistics
flows = defaultdict(lambda: {
    'Flow Duration': 0,
    'Total Fwd Packets': 0,
    'Total Backward Packets': 0,
    'Total Length of Fwd Packets': 0,
    'Total Length of Bwd Packets': 0,
    'Fwd Packet Length Max': 0,
    'Fwd Packet Length Min': float('inf'),
    'Fwd Packet Length Mean': 0,
    'Fwd Packet Length Std': [],
    'Bwd Packet Length Max': 0,
    'Bwd Packet Length Min': float('inf'),
    'Bwd Packet Length Mean': 0,
    'Bwd Packet Length Std': [],
    'Flow Bytes/s': 0,
    'Flow Packets/s': 0,
    'Flow IAT Mean': 0,
    'Fwd IAT Total': 0,
    'Bwd IAT Total': 0,
    'Fwd PSH Flags': 0,
    'Bwd PSH Flags': 0,
    'Fwd Header Length': 0,
    'Bwd Header Length': 0
})


# Function to extract flow key
def get_flow_key(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if TCP in packet or UDP in packet else 0
        dst_port = packet.dport if TCP in packet or UDP in packet else 0
        protocol = packet[IP].proto
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    return None


# Iterate over packets to calculate flow features
for packet in packets:
    flow_key = get_flow_key(packet)
    if flow_key and IP in packet:
        flow = flows[flow_key]
        timestamp = packet.time

        # Forward vs Backward packet
        if packet[IP].src == flow_key[0]:
            direction = 'fwd'
        else:
            direction = 'bwd'

        # Update flow duration (assuming flow starts at first packet)
        if flow['Flow Duration'] == 0:
            flow['Flow Duration'] = timestamp
        else:
            flow['Flow Duration'] = max(flow['Flow Duration'], timestamp - flow['Flow Duration'])

        # Packet length and counts
        pkt_length = len(packet)

        if direction == 'fwd':
            flow['Total Fwd Packets'] += 1
            flow['Total Length of Fwd Packets'] += pkt_length
            flow['Fwd Packet Length Max'] = max(flow['Fwd Packet Length Max'], pkt_length)
            flow['Fwd Packet Length Min'] = min(flow['Fwd Packet Length Min'], pkt_length)
            flow['Fwd Packet Length Std'].append(pkt_length)
        else:
            flow['Total Backward Packets'] += 1
            flow['Total Length of Bwd Packets'] += pkt_length
            flow['Bwd Packet Length Max'] = max(flow['Bwd Packet Length Max'], pkt_length)
            flow['Bwd Packet Length Min'] = min(flow['Bwd Packet Length Min'], pkt_length)
            flow['Bwd Packet Length Std'].append(pkt_length)

        # Header lengths (using IP header length for simplicity)
        if direction == 'fwd':
            flow['Fwd Header Length'] += packet[IP].ihl * 4
        else:
            flow['Bwd Header Length'] += packet[IP].ihl * 4

# Calculate remaining statistics
for flow_key, flow in flows.items():
    if flow['Total Fwd Packets'] > 0:
        flow['Fwd Packet Length Mean'] = flow['Total Length of Fwd Packets'] / flow['Total Fwd Packets']
        flow['Fwd Packet Length Std'] = pd.Series(flow['Fwd Packet Length Std']).std()
    if flow['Total Backward Packets'] > 0:
        flow['Bwd Packet Length Mean'] = flow['Total Length of Bwd Packets'] / flow['Total Backward Packets']
        flow['Bwd Packet Length Std'] = pd.Series(flow['Bwd Packet Length Std']).std()

# Convert flows to a DataFrame
flow_df = pd.DataFrame.from_dict(flows, orient='index')

# Save to CSV
flow_df.to_csv('processed_traffic.csv', index=False)
print("Packet data successfully exported to processed_traffic.csv")
