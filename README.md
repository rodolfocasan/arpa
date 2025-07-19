# ARPA - Herramienta de Análisis y Manipulación de Red (requiere ROOT)
ARPA es un programa de Python diseñado para analizar y manipular redes locales utilizando técnicas de ARP (Address Resolution Protocol). Permite listar dispositivos conectados, obtener información detallada sobre ellos y desconectarlos de la red mediante ARP spoofing.

## Características
- **Listar dispositivos**: Escanea la red local y muestra una lista de dispositivos conectados con sus direcciones IP y MAC.
- **Desconectar dispositivos**: Permite desconectar uno o todos los dispositivos de la red mediante un ataque de ARP spoofing continuo.

## Requisitos
- Python 3.10.13+
- Permisos de administrador (para operaciones de red como ARP spoofing)
- Diseñado para funcionar en Linux.

## Instalación
1. Clona este repositorio:
   ```bash
   git clone https://github.com/rodolfocasan/arpa.git
   ```
   ```bash
   cd arpa
   ```
   ```bash
   pip install -r DOCs/requirements.txt
   ```
2. Asegúrate de tener permisos de administrador para ejecutar operaciones de red.

## Uso
Ejecuta el script con los siguientes argumentos:

- **Listar dispositivos conectados**:
   ```bash
   sudo python3 main.py -l
   ```
   Escanea la red y muestra una lista de dispositivos con sus IP y MAC.

- **Desconectar un dispositivo**:
   ```bash
   sudo python3 main.py -k <IP o MAC>
   ```
   Inicia un ataque ARP spoofing para desconectar un dispositivo específico.

- **Desconectar todos los dispositivos**:
   ```bash
   sudo python3 main.py -k all
   ```
   Desconecta todos los dispositivos de la red, excluyendo el gateway.

**Nota**: Los ataques de desconexión son continuos y deben detenerse manualmente con `Ctrl+C`, lo que restaurará las tablas ARP.

## Advertencias y Limitaciones
- **Uso ético**: Este script debe usarse solo en redes donde tengas permiso explícito. El uso no autorizado puede ser ilegal.
- **Limitaciones**:
  - El escaneo puede no detectar dispositivos que no respondan a ARP.
  - La desconexión puede fallar en redes con medidas de seguridad avanzadas.

