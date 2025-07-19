#!/usr/bin/env python3
# network_utils.py
import subprocess
import scapy.all as scapy





def get_mac(ip):
    """ Obtiene la dirección MAC asociada a una IP mediante un ping ARP """
    # Realiza un ping ARP a la IP especificada con un tiempo de espera determinado (segundos)
    ans, _ = scapy.arping(
        ip,
        timeout = 2,
        verbose = True
    )
    
    # Itera sobre las respuestas obtenidas
    for s, r in ans:
        return r.hwsrc      # Retorna la dirección MAC (hwsrc) de la primera respuesta válida
    return None             # Retorna None si no se encuentra una MAC asociada


def get_gateway_ip():
    """ Obtiene la IP del gateway predeterminado del sistema en Linux """
    # Usa 'ip route' para encontrar el gateway predeterminado
    result = subprocess.run(
        "ip route | grep default",
        shell = True,
        capture_output = True,
        text = True,
    )
    
    # Parsea la salida para extraer la IP del gateway
    if result.stdout:
        return result.stdout.split()[2]
    
    # Retorna None si no se encuentra el gateway
    return None


def scan(ip_range):
    """ Escanea la red para descubrir dispositivos y sus direcciones IP/MAC """
    # Crea una solicitud ARP para el rango de IP especificado
    arp_request = scapy.ARP(pdst=ip_range)
    
    # Configura un frame Ethernet con dirección de broadcast (todos los dispositivos)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combina la solicitud ARP con el frame de broadcast
    request_broadcast = broadcast / arp_request
    
    # Envía la solicitud y recibe respuestas, con un timeout determinado (s)
    answered = scapy.srp(request_broadcast, timeout=2, verbose=True)[0]
    
    # Itera sobre las respuestas y guarda IP/MAC de cada dispositivo
    devices = []
    for element in answered:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices