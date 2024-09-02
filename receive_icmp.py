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

# Función para recibir y procesar paquetes ICMP
def receive_icmp_tunnel():
    try:
        # Crear socket para recibir paquetes ICMP
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.bind(("0.0.0.0", 0))  # Bind a cualquier IP local y puerto 0
            print("Escuchando paquetes ICMP...")
            
            while True:
                packet, addr = sock.recvfrom(65565)  # Asegúrate de tener un buffer grande suficiente
                icmp_header = packet[20:28]  # El encabezado ICMP comienza después del encabezado IP
                icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)
                
                # Verificar que el paquete sea un Echo Request (tipo 8)
                if icmp_type == 8:
                    # Extraer los datos del paquete ICMP (payload)
                    payload = packet[28:]  # El payload comienza después del encabezado ICMP
                    print(f"Paquete ICMP recibido de {addr[0]}")
                    print(f"Mensaje: {payload.decode('utf-8')}")
                else:
                    print(f"Paquete ICMP ignorado: Tipo {icmp_type}")
    except Exception as e:
        print(f"Error: {e}")

# Main
if __name__ == "__main__":
    receive_icmp_tunnel()
