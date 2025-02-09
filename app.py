from scapy.all import ARP, Ether, srp
import time

def escanear_red(ip_range):
    """Escanea la red para encontrar dispositivos activos."""
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]
    
    dispositivos = []
    for sent, received in result:
        dispositivos.append({'ip': received.psrc, 'mac': received.hwsrc})
    return dispositivos

def mostrar_dispositivos(dispositivos):
    """Muestra los dispositivos detectados."""
    print("\nDispositivos encontrados:")
    print("IP\t\tMAC Address")
    print("----------------------------------")
    for device in dispositivos:
        print(f"{device['ip']}	{device['mac']}")

def monitoreo_continuo(ip_range, intervalo=10):
    """Monitorea la red en busca de cambios."""
    print("Iniciando monitoreo de la red...")
    dispositivos_previos = set()
    
    while True:
        dispositivos = escanear_red(ip_range)
        dispositivos_actuales = set((d['ip'], d['mac']) for d in dispositivos)
        
        if dispositivos_actuales != dispositivos_previos:
            print("\nCambio detectado en la red:")
            mostrar_dispositivos(dispositivos)
            dispositivos_previos = dispositivos_actuales
        
        time.sleep(intervalo)

if __name__ == "__main__":
    red = "192.168.1.0/24"  # Ajusta este rango según tu red
    monitoreo_continuo(red)
