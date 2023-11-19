from scapy.all import ARP, Ether, srp
import dearpygui.dearpygui as dpg
import threading
import socket
import time

dpg.create_context()

with dpg.window(label="IP Scan", width=600, height=220, pos=(0, 211), no_resize=True, no_close=True, no_collapse=True, no_move=True, no_scrollbar=True):
    def scan_ip():
        dpg.show_item("ip_scan_loading")
        ip_range = "192.168.1.1/24"
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        ip_mac_pairs = [(received.psrc, received.hwsrc) for sent, received in result]
        output = "\n".join([f"{ip} - {mac}" for ip, mac in ip_mac_pairs])
        dpg.set_value("ip_output", output)
        dpg.hide_item("ip_scan_loading")

    dpg.add_input_text(multiline=True, readonly=True, tag="ip_output")
    dpg.add_button(label="Scan", callback=scan_ip)
    dpg.add_loading_indicator(show=False, tag="ip_scan_loading")

with dpg.window(label="UDP", width=300, height=211, pos=(300, 0), no_resize=True, no_close=True, no_collapse=True, no_move=True, no_scrollbar=True):
    def udp_send(server_address, message):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.sendto(message.encode(), server_address)
            client_socket.close()
        except Exception as e:
            print(e)
            pass

    def udp_client():
        try:
            server_address = (dpg.get_value("udp_ip"), int(dpg.get_value("udp_port")))
            message = dpg.get_value("udp_message")
            count = int(dpg.get_value("udp_msg_count"))

            threads = []
            for _ in range(count):
                thread = threading.Thread(target=udp_send, args=(server_address, message))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            dpg.set_value("udp_true_result", "True")
            time.sleep(1)
            dpg.set_value("udp_true_result", "")
        except Exception as e:
            dpg.set_value("udp_false_result", "False")
            time.sleep(1)
            dpg.set_value("udp_false_result", "")
            print(e)

    dpg.add_input_text(label="Address", default_value="127.0.0.1", tag="udp_ip")
    dpg.add_input_text(label="Port", default_value="65535", tag="udp_port")
    dpg.add_input_text(label="Message", default_value="Test!", tag="udp_message")
    dpg.add_input_text(label="Count", default_value="1", tag="udp_msg_count")
    dpg.add_button(label="Send", callback=udp_client)
    dpg.add_text(tag="udp_true_result", color=(0, 128, 0))
    dpg.add_text(tag="udp_false_result", color=(255, 0, 0))

with dpg.window(label="TCP", width=300, height=211, no_collapse=True, no_move=True, no_close=True, no_resize=True, no_scrollbar=True):
    def tcp_send(server_address, message):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(server_address)
            client_socket.sendall(message.encode())
            client_socket.close()
        except Exception as e:
            print(e)
            pass

    def tcp_client():
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (dpg.get_value("tcp_url"), int(dpg.get_value("tcp_port")))

        client_socket.connect(server_address)

        try:
            message = dpg.get_value("tcp_message")
            count = int(dpg.get_value("tcp_msg_count"))

            threads = []
            for _ in range(count):
                thread = threading.Thread(target=tcp_send, args=(server_address, message))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            dpg.set_value("tcp_true_result", "True")
            time.sleep(1)
            dpg.set_value("tcp_true_result", "")
        except Exception as e:
            dpg.set_value("tcp_false_result", "False")
            time.sleep(1)
            dpg.set_value("tcp_false_result", "")
            print(e)

        client_socket.close()

    dpg.add_input_text(label="Address", default_value="google.com", tag="tcp_url")
    dpg.add_input_text(label="Port", default_value="80", tag="tcp_port")
    dpg.add_input_text(label="Message", default_value="Hello, server!", tag="tcp_message")
    dpg.add_input_text(label="Count", default_value="1", tag="tcp_msg_count")
    dpg.add_button(label="Send", callback=tcp_client)
    dpg.add_text(tag="tcp_true_result", color=(0, 128, 0))
    dpg.add_text(tag="tcp_false_result", color=(255, 0, 0))

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
dpg.create_viewport(title='Network tool by Bt08s', width=616, height=470)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()
