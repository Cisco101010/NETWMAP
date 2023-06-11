import os
from scapy.all import *
from prettytable import PrettyTable
import nmap

# Creamos la tabla para mostrar los resultados
table = PrettyTable()
table.field_names = ["IP Address", "MAC Address", "Device Type", "Open Ports"]
table.align = 'l'  # Set alignment to left for all columns

nm = nmap.PortScanner()

# Lista para almacenar las direcciones IP ya mostradas
shown_ips = []

def process_packet(packet):
    if packet.haslayer(ARP):
        # Obtenemos la dirección IP y MAC del dispositivo
        ip_address = packet[ARP].psrc
        mac_address = packet[ARP].hwsrc

        # Evitamos duplicados en la tabla
        if ip_address in shown_ips:
            return

        shown_ips.append(ip_address)

        # Escaneamos los puertos del dispositivo
        nm.scan(hosts=ip_address, arguments='-sS -O --script-timeout 10s')
        port_data = nm[ip_address]

        # Obtenemos el tipo de dispositivo
        device_type = port_data['osmatch'][0]['name'] if 'osmatch' in port_data and port_data['osmatch'] else ""

        # Obtenemos los puertos abiertos
        open_ports = ", ".join(str(port) for port in port_data['tcp'].keys()) if 'tcp' in port_data else ""

        # Agregamos los datos a la tabla
        table.add_row([ip_address, mac_address, device_type, open_ports])

        # Limpiamos la pantalla antes de imprimir la tabla actualizada
        os.system('cls' if os.name == 'nt' else 'clear')

        # Imprimimos la tabla actualizada
        print(table)

# Función principal
def main():
    # Ajusta tu interfaz aquí
    interface = 'interface'

    # Imprimir banner
    banner = """
  ___       ___       ___       ___       ___       ___       ___       ___
  /\  \     /\  \     /\  \     /\__\     /\  \     /\__\     /\  \     /\  \\
 /::\  \   _\:\  \   /::\  \   /:/ _/_   /::\  \   /:/ _/_   /::\  \   /::\  \\
/:/\:\__\ /\/::\__\ /\:\:\__\ /::-"\__\ /:/\:\__\ |::L/\__\ /::\:\__\ /::\:\__\\
\:\/:/  / \::/\/__/ \:\:\/__/ \;:;-",-" \:\/:/  / |::::/  / \:\:\/  / \;:::/  /
 \::/  /   \:\__\    \::/  /   |:|  |    \::/  /   L;;/__/   \:\/  /   |:\/__/
  \/__/     \/__/     \/__/     \|__|     \/__/               \/__/     \|__|
                          

                             Welcome to NETWMAP
          

                          Developed by Erick Cedeno


                                  CISCO-101


                      be patient while the scan runs..... 


                       -----    HAPPY-HACKING  ----- :)




"""
    print("\033[1;34;48m" + banner + "\033[0m")

    # Iniciamos la captura de paquetes
    sniff(prn=process_packet, filter="arp", iface="interface", store=0)

if __name__ == '__main__':
     main()