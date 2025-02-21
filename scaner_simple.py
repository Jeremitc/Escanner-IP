from scapy.all import IP, TCP, sr1

target_ip = "8.243.126.254"  #IP cambiable , IP changes
puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389]

def scan_port(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")  # Enviar paquete SYN
    response = sr1(pkt, timeout=1, verbose=0)

    if response is None:
        print(f"🔴 {port} - No responde")
    elif response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK recibido
        print(f"🟢 {port} - **ABIERTO**")
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:  # RST-ACK recibido
        print(f"🔴 {port} - Cerrado")
    else:
        print(f"⚠️ {port} - Estado desconocido")

print(f"Escaneando {target_ip}...\n")
for port in puertos_comunes:
    scan_port(target_ip, port)
