#!/usr/bin/env python3
# cli_handler.py
import argparse





def get_arguments():
    """ Procesa los argumentos de línea de comandos """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--list", action="store_true", help="Listar dispositivos conectados en la red")
    group.add_argument("-k", "--kick", dest="target", help="Desconectar dispositivo(s) de la red (IP, MAC o 'all' para todos)")
    args = parser.parse_args()
    return args