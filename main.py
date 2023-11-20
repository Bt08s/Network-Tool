from scapy.all import ARP, Ether, srp
import dearpygui.dearpygui as dpg
import threading
import socket
import time

dpg.create_context()

with dpg.window(label="Port scan", width=300, height=340, pos=(600, 0), no_resize=True, no_close=True, no_collapse=True, no_move=True, no_scrollbar=True):
    def scan_port(ip, port):
        global open_ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))
            sock.close()
            open_ports.append(port)
        except:
            pass


    def port_scanner():
        global open_ports
        open_ports = []

        ip = dpg.get_value("port_scanner_ip")
        start_port = int(dpg.get_value("port_scanner_start_port"))
        end_port = int(dpg.get_value("port_scanner_end_port"))

        print(f"[PORT SCAN] IP {ip} Port {start_port}:{end_port}")
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(ip, port))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        dpg.set_value("port_scan_output", "\n".join(map(str, open_ports)))

    dpg.add_input_text(label="IP", tag="port_scanner_ip")
    dpg.add_input_text(label="Start port", default_value=1, tag="port_scanner_start_port")
    dpg.add_input_text(label="End port", default_value=65535, tag="port_scanner_end_port")
    dpg.add_button(label="Scan", callback=port_scanner)
    dpg.add_spacer(parent=10)
    dpg.add_input_text(multiline=True, readonly=True, tag="port_scan_output", height=190)

with dpg.window(label="IP scan", width=600, height=175, pos=(0, 165), no_resize=True, no_close=True, no_collapse=True, no_move=True, no_scrollbar=True):
    def scan_ip():
        print("[IP SCAN] Range 192.168.1.1/24")
        ip_range = "192.168.1.1/24"
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        ip_mac_pairs = [(received.psrc, received.hwsrc) for sent, received in result]
        output = "\n".join([f"{ip} - {mac}" for ip, mac in ip_mac_pairs])
        dpg.set_value("ip_output", output)

    dpg.add_input_text(multiline=True, readonly=True, tag="ip_output")
    dpg.add_button(label="Scan", callback=scan_ip)

with dpg.window(label="UDP", width=300, height=165, pos=(300, 0), no_resize=True, no_close=True, no_collapse=True, no_move=True, no_scrollbar=True):
    def udp_send(address, data):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(data.encode(), address)
            client.close()
            print(f"[UDP SOCKET CLIENT] IP {address} Data {data}")
        except Exception as e:
            print(e)
            pass

    def udp_client():
        try:
            server_address = (dpg.get_value("udp_ip"), int(dpg.get_value("udp_port")))
            data = dpg.get_value("udp_data")
            count = int(dpg.get_value("udp_msg_count"))

            threads = []
            for _ in range(count):
                thread = threading.Thread(target=udp_send, args=(server_address, data))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            print("[UDP CLIENT LOG] Finished successfully")
        except Exception as e:
            print(f"[TCP CLIENT LOG] Error {e}")

    dpg.add_input_text(label="Address", tag="udp_ip")
    dpg.add_input_text(label="Port", tag="udp_port")
    dpg.add_input_text(label="Data", tag="udp_data")
    dpg.add_input_text(label="Count", default_value="1", tag="udp_msg_count")
    dpg.add_button(label="Send", callback=udp_client)
    dpg.add_text(tag="udp_result", color=(255, 165, 0))

with dpg.window(label="TCP", width=300, height=165, no_collapse=True, no_move=True, no_close=True, no_resize=True, no_scrollbar=True):
    def tcp_send(address, data):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(address)
            client.sendall(data.encode())
            client.close()
            print(f"[TCP SOCKET CLIENT] IP {address} Data {data}")
        except Exception as e:
            print(e)
            pass

    def tcp_client():
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (dpg.get_value("tcp_url"), int(dpg.get_value("tcp_port")))

        client_socket.connect(server_address)

        try:
            data = dpg.get_value("tcp_data")
            count = int(dpg.get_value("tcp_msg_count"))

            threads = []
            for _ in range(count):
                thread = threading.Thread(target=tcp_send, args=(server_address, data))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            print("[TCP CLIENT LOG] Finished successfully")
        except Exception as e:
            print(f"[TCP CLIENT LOG] Error {e}")
        client_socket.close()

    dpg.add_input_text(label="Address", tag="tcp_url")
    dpg.add_input_text(label="Port", tag="tcp_port")
    dpg.add_input_text(label="Data", tag="tcp_data")
    dpg.add_input_text(label="Count", default_value="1", tag="tcp_msg_count")
    dpg.add_button(label="Send", callback=tcp_client)
    dpg.add_text(tag="tcp_result", color=(255, 165, 0))

with dpg.theme() as global_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 3)
        dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 4, 4)
        dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 5, 5)

dpg.bind_theme(global_theme)
dpg.create_viewport(title='Network tool by Bt08s', width=916, height=379)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()
