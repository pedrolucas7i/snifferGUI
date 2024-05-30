import tkinter as tk
from scapy.all import sniff, AsyncSniffer, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys
import os

# Lista para armazenar pacotes capturados
packets = []

# Função de callback para processar pacotes
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_info = f"IP Packet: {ip_src} -> {ip_dst}    (Double Click to View More Info)"
        listbox.insert(tk.END, packet_info)
        listbox.yview_moveto(1.0)  # Autoscroll para o final
        packets.append(packet)

# Função para iniciar a captura de pacotes
def start_sniffing():
    sniffer = AsyncSniffer(prn=packet_callback, store=False)
    sniffer.start()
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    global sniffer_thread
    sniffer_thread = sniffer

# Função para parar a captura de pacotes
def stop_sniffing():
    sniffer_thread.stop()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Função para converter pacotes para um formato legível
def packet_to_readable(packet):
    readable_data = []
    if IP in packet:
        readable_data.append(f"Source IP: {packet[IP].src}")
        readable_data.append(f"Destination IP: {packet[IP].dst}")
        readable_data.append(f"Protocol: {packet[IP].proto}")
    if TCP in packet:
        readable_data.append(f"Source Port: {packet[TCP].sport}")
        readable_data.append(f"Destination Port: {packet[TCP].dport}")
        readable_data.append(f"Flags: {packet[TCP].flags}")
    if UDP in packet:
        readable_data.append(f"Source Port: {packet[UDP].sport}")
        readable_data.append(f"Destination Port: {packet[UDP].dport}")
    if ICMP in packet:
        readable_data.append(f"ICMP Type: {packet[ICMP].type}")
        readable_data.append(f"ICMP Code: {packet[ICMP].code}")
    readable_data.append(f"Raw Data: {bytes(packet)}")
    return '\n'.join(readable_data)

# Função para exibir dados do pacote
def show_packet_details(event):
    selected_index = listbox.curselection()
    if selected_index:
        packet = packets[selected_index[0]]
        readable_data = packet_to_readable(packet)
        hex_data = hexdump(packet, dump=True)
        
        details_window = tk.Toplevel(root)
        details_window.title("Packet Details")

        # Frame para dados legíveis
        readable_frame = tk.Frame(details_window)
        readable_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        readable_label = tk.Label(readable_frame, text="Readable Data")
        readable_label.pack()

        readable_text = tk.Text(readable_frame, wrap=tk.NONE)
        readable_text.insert(tk.END, readable_data)
        readable_text.pack(expand=True, fill=tk.BOTH)

        # Frame para dados hexadecimais
        hex_frame = tk.Frame(details_window)
        hex_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        hex_label = tk.Label(hex_frame, text="Hex Data")
        hex_label.pack()

        hex_text = tk.Text(hex_frame, wrap=tk.NONE)
        hex_text.insert(tk.END, hex_data)
        hex_text.pack(expand=True, fill=tk.BOTH)

        readable_scrollbar = tk.Scrollbar(readable_frame, orient=tk.HORIZONTAL, command=readable_text.xview)
        readable_text.configure(xscrollcommand=readable_scrollbar.set)
        readable_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        hex_scrollbar = tk.Scrollbar(hex_frame, orient=tk.HORIZONTAL, command=hex_text.xview)
        hex_text.configure(xscrollcommand=hex_scrollbar.set)
        hex_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Criação da interface gráfica
root = tk.Tk()
root.title("Packet Sniffer")
icon = tk.PhotoImage(file=resource_path("icon-sniffer.png"))
root.iconphoto(False, icon)
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

scrollbar = tk.Scrollbar(frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = tk.Listbox(frame, width=100, height=20, yscrollcommand=scrollbar.set)
listbox.pack(side=tk.LEFT, fill=tk.BOTH)
listbox.bind('<Double-1>', show_packet_details)
scrollbar.config(command=listbox.yview)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
stop_button.pack(side=tk.RIGHT, padx=10, pady=10)

root.mainloop()
