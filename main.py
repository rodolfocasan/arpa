#!/usr/bin/env python3
# main.py
from cli_handler import get_arguments
from network_utils import get_gateway_ip, scan
from arp_operations import kick, kick_all

from ascii_art import logo_01





def main():
    """ Punto de entrada principal para ejecutar las funcionalidades del programa """
    args = get_arguments()
    gateway = get_gateway_ip()
    
    # Verifica que se haya encontrado el gateway
    if not gateway:
        print("[-] No se pudo obtener la IP del gateway. Verifica tu conexión de red.")
        return
    
    print(logo_01("1.0.0"))
    
    if args.list:
        print("[*] Escaneando red...")
        ip_range = gateway + "/24"
        devices = scan(ip_range)
        if not devices:
            print("[-] No se encontraron dispositivos en la red.")
            return
        
        print(f"[+] Dispositivos encontrados en la red {ip_range}:")
        for idx, device in enumerate(devices):
            print(f"{idx+1}. IP: {device['ip']}, MAC: {device['mac']}")
    elif args.target:
        if args.target.lower() == "all":
            kick_all(gateway)
        else:
            kick(args.target, gateway)
    else:
        print("[-] Argumento inválido. Usa -l para listar dispositivos o -k <IP/MAC> para desconectar.")





if __name__ == "__main__":
    main()