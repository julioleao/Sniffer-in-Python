# -*- coding: utf-8 -*-
import socket
import struct

def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	print('+---------------------------------------+')
	print('+----------FILTRAR PACOTES IPv4---------+')
	print('|                                       |')
	print('|[ 1 ] ICMP                             |')
	print('|[ 2 ] TCP                              |')
	print('|[ 3 ] UDP                              |')
	print('|[ 4 ] Capturar todos                   |')
	print('|                                       |')
	print('+---------------------------------------+')
	print('+---------------------------------------+')
	op = int(input())
	if op >= 1 and op <= 4:
		while True:
			raw_data, addr = conn.recvfrom(65536)
			dest_mac, src_mac, eth_proto, data = frame_internet(raw_data)
			
			
			#IPv4
			if eth_proto == 8:
				(version, header_lenght, ttl, proto, src, target, data) = ipv4_packet(data)
						
				
				#ICMP
				if proto == 1:
					icmp_type, code, checksum, data = icmp_packet(data)
					if op == 1 or op == 4:
						frame_eth_format(dest_mac, src_mac, eth_proto)
						ipv4_format(version, header_lenght, ttl, proto, src, target)
						print('+-----------------------------------------ICMP------------------------------------------+')
						print('|Tipo: {}\t| Código: {}\t\t\t| Checksum: {}  \t\t\t|'.format(icmp_type, code, checksum))
						print('+---------------------------------------------------------------------------------------+')
							
				#TCP
				elif proto == 6:
					(src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp(data)
					if op == 2 or op == 4:
						frame_eth_format(dest_mac, src_mac, eth_proto)
						ipv4_format(version, header_lenght, ttl, proto, src, target)
						print('+-----------------------------------------TCP-------------------------------------------+')
						print('|Porta de Origem: {}\t\t| Porta de Destino: {}   \t\t\t\t|'.format(src_port, dest_port))
						print('|N de Sequencia: {}\t| N de Confirmacao (ACK): {}\t\t\t|'.format(sequence, ack))
						print('+----------------------------------------Flags------------------------------------------+')
						print('|URG: {}\t| ACK: {}\t| PSH: {}\t| RST: {}\t| SYN: {}\t| FIN: {}\t|'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
						print('+---------------------------------------------------------------------------------------+')
				
				#UDP
				elif proto == 17:
					src_port, dest_port, length, data = udp(data)
					if op == 3 or op == 4:
						frame_eth_format(dest_mac, src_mac, eth_proto)
						ipv4_format(version, header_lenght, ttl, proto, src, target)
						print('+-----------------------------------------UDP-------------------------------------------+')
						print('|Porta de Origem: {}\t| Porta e Destino: {}  \t| Tamanho: {}    \t\t|'.format(src_port, dest_port, length))
						print('+---------------------------------------------------------------------------------------+')
	else:
		print('Opcao invalida!')

#Desempacotar frame Internet
def frame_internet(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
	 
#Retornar endereço MAC formatado (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()
	
#Desempacotar pacote IPV4
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
		
#Retornar endereço IPV4 formatado (127.20.10.1)
def ipv4(addr):
	return '.'.join(map(str, addr))
	
#Desempacotar pacote ICMP
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]
	
#Desempacotar pacote TCP
def tcp(data):
	(src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	
	return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Desempacotar segmento UDP
def udp(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]

#Mostrar na tela o frame Internet formatado	
def frame_eth_format(dest_mac, src_mac, eth_proto):
	print('\n\n+------------------------------------Frame Internet-------------------------------------+')
	print('|MAC de Destino: {} | MAC de Origem: {} | Protocolo: {}\t|'.format(dest_mac, src_mac, eth_proto))

#Mostrar na tela o pacote IPv4 formatado
def ipv4_format(version, header_lenght, ttl, proto, src, target):
	print ('+--------------------------------------Pacote IPv4--------------------------------------+')
	print ('|Versão: {}\t| Tamanho do Cabecalho: {}\t| Tempo de Vida: {}\t\t\t|'.format(version, header_lenght, ttl))
	print ('|Protocolo: {}\t| IP de Origem: {}\t| IP de Destino: {}      \t|'.format(proto, src, target))
	
main()
