import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, AsyncSniffer, hexdump
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Lista para armazenar pacotes capturados
packets = []
filtered_packets = []
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Função de callback para processar pacotes
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        packet_info = f"{protocol} Packet: {ip_src} -> {ip_dst}    (Double Click to View More Info)"
        packets.append((protocol, packet_info, packet))
        
        # Atualiza contagem de protocolos
        protocol_counts[protocol] += 1
        
        update_chart()
        update_listbox()

# Função para iniciar a captura de pacotes
def start_sniffing():
    global sniffer_thread
    sniffer_thread = AsyncSniffer(prn=packet_callback, store=False)
    sniffer_thread.start()
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

# Função para parar a captura de pacotes
def stop_sniffing():
    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.stop()
        sniffer_thread.join()  # Assegura que o thread é encerrado antes de continuar
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
        packet = filtered_packets[selected_index[0]]
        readable_data = packet_to_readable(packet[2])
        hex_data = hexdump(packet[2], dump=True)
        
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

# Função para atualizar o gráfico
def update_chart():
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    ax.clear()
    ax.bar(protocols, counts, color=['blue', 'green', 'red', 'orange'])
    ax.set_title('Protocol Count')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Count')
    chart.draw()

# Função para atualizar a listbox com base no protocolo selecionado
def update_listbox(*args):
    listbox.delete(0, tk.END)
    global filtered_packets
    filtered_packets = [pkt for pkt in packets if pkt[0] == selected_protocol.get() or selected_protocol.get() == "All"]
    for pkt in filtered_packets:
        listbox.insert(tk.END, pkt[1])
    listbox.yview_moveto(1.0)  # Autoscroll para o final

# Criação da interface gráfica
root = tk.Tk()
root.title("Packet Sniffer")
icon = tk.PhotoImage(file=resource_path("icon-sniffer.png"))
root.iconphoto(False, icon)

# Variável tkinter para o protocolo selecionado
selected_protocol = tk.StringVar()
selected_protocol.set("All")

# Frame principal
frame = tk.Frame(root)
frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Listbox com scrollbar
listbox_frame = tk.Frame(frame)
listbox_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(listbox_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = tk.Listbox(listbox_frame, width=50, height=20, yscrollcommand=scrollbar.set)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
listbox.bind('<Double-1>', show_packet_details)
scrollbar.config(command=listbox.yview)

# Frame do gráfico de protocolos
chart_frame = tk.Frame(frame)
chart_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

fig, ax = plt.subplots(figsize=(6, 4))  # Define o tamanho do gráfico
chart = FigureCanvasTkAgg(fig, chart_frame)
chart.get_tk_widget().pack(fill=tk.BOTH, expand=True)

# Combobox para selecionar protocolo
protocol_label = tk.Label(root, text="Select Protocol:")
protocol_label.pack(side=tk.LEFT, padx=5)

protocol_combobox = ttk.Combobox(root, textvariable=selected_protocol)
protocol_combobox['values'] = ("All", "TCP", "UDP", "ICMP", "Other")
protocol_combobox.current(0)
protocol_combobox.pack(side=tk.LEFT, padx=5)

# Botões de controle
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
stop_button.pack(side=tk.RIGHT, padx=10)

selected_protocol.trace_add("write", update_listbox)  # Atualiza listbox quando o protocolo é alterado

root.mainloop()
