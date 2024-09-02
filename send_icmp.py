import os
import socket
import struct

# Definir función para calcular checksum
def calculate_checksum(source_string):
    checksum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        checksum += this_val
        checksum = checksum & 0xffffffff
        count += 2

    if count_to < len(source_string):
        checksum += source_string[len(source_string) - 1]
        checksum = checksum & 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    answer = ~checksum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# Función para enviar paquete ICMP con datos personalizados (tunneling)
def send_icmp_tunnel(target_ip, message):
    try:
        # Crear encabezado ICMP
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xFFFF  # Usamos el PID del proceso como identificador
        icmp_seq = 1

        # Encapsulamos el mensaje en la carga útil del paquete ICMP
        payload = message.encode()

        # Construir paquete ICMP
        icmp_header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        packet = icmp_header + payload

        # Calcular checksum del paquete
        icmp_checksum = calculate_checksum(packet)
        icmp_header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_seq)
        packet = icmp_header + payload

        # Crear socket RAW
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.sendto(packet, (target_ip, 0))
            print(f"Paquete ICMP enviado a {target_ip} con el mensaje: {message}")
    except Exception as e:
        print(f"Error enviando paquete ICMP: {e}")

# Main
if __name__ == "__main__":
    # IP del destino
    target_ip = "10.186.0.2"  # Cambia a la IP de destino

    # Mensaje a enviar dentro del ICMP
    message = "R0otAcc.es - 𝗨𝗻𝗶𝗱𝗼𝘀 𝗽𝗮𝗿𝗮 𝗔𝗽𝗿𝗲𝗻𝗱𝗲𝗿 𝘆 𝗣𝗿𝗼𝘁𝗲𝗴𝗲𝗿"

    # Enviar el paquete ICMP
    send_icmp_tunnel(target_ip, message)
