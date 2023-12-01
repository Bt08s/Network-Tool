from scapy.all import ARP, Ether, srp
import socket
import nmap
import time
import sys
import os

print("Scanning...")


def is_admin():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception as e:
        print(f"Error {e}")


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
            'mac': mac,
            'hostname': get_hostname(received.psrc)
        })
    return devices


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "N/A"
    return hostname


def get_os(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')
    os_info = "N/A"

    try:
        if nm[ip]['osmatch'] and nm[ip]['osmatch'][0]['osclass']:
            os_info = nm[ip]['osmatch'][0]['osclass'][0]['osfamily']
    except KeyError:
        pass

    return os_info


def get_devices_in_network(network):
    while True:
        devices = scan(network)
        os.system('cls' if os.name == 'nt' else 'clear')
        print("IP Address\t\tMAC Address\t\t\tHostname\t\tOS")
        print("----------------------------------------------------------------------------------")
        for device in devices:
            os_info = get_os(device['ip'])
            print(f"{device['ip']}\t\t{device['mac']}\t\t{device['hostname']}\t\t{os_info}")
        time.sleep(5)


if not is_admin():
    if os.name == 'nt':
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    else:
        os.system(f"sudo {sys.executable} {' '.join(sys.argv[1:])}")

target_network = "192.168.1.0/24"
get_devices_in_network(target_network)
