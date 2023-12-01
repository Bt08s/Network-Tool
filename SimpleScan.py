from scapy.all import ARP, Ether, srp
import time
import os

print("Scanning...")


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=0)[0]
    return result[0][1].hwsrc


def scan(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        mac = received.hwsrc
        devices.append({
            'ip': received.psrc,
            'mac': mac
        })
    return devices


def get_devices_in_network(network):
    while True:
        devices = scan(network)
        os.system('cls' if os.name == 'nt' else 'clear')
        print("IP Address\t\tMAC Address")
        print("-----------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
        time.sleep(5)


target_network = "192.168.1.0/24"
get_devices_in_network(target_network)
