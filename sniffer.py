# -*- coding: utf-8 -*-
import socket
import struct

def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	while True:
		raw_data, addr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = frame_internet(raw_data)
		print('\nFrame Internet')
		print('\tMAC de Destino: {}, MAC de Origem: {}, Protocolo: {}'.format(dest_mac, src_mac, eth_proto))
		
		#IPv4
		if eth_proto == 8:
			(version, header_lenght, ttl, proto, src, target, data) = ipv4_packet(data)
			print ('Pacote IPv4')
			print ('\tVersão: {}, Tamanho do Cabecalho: {}, Tempo de Vida: {}'.format(version, header_lenght, ttl))
			print ('\tProtocolo: {}, IP de Origem: {}, IP de Destino: {}'.format(proto, src, target))
		
			#ICMP
			if proto == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				print('Pacote ICMP: ')
				print('\tTipo: {}, Código: {}, Checksum: {},'.format(icmp_type, code, checksum))
							
			#TCP
			elif proto == 6:
				(src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp(data)
				print('TCP')
				print('\tPorta de Origem: {}, Porta de Destino: {}'.format(src_port, dest_port))
				print('\tN de Sequencia: {}, N de Confirmacao (ACK): {}'.format(sequence, ack))
				print('Flags')
				print('\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				
				
			#UDP
			elif proto == 17:
				src_port, dest_port, length, data = udp(data)
				print('UDP')
				print('\tPorta de Origem: {}, Porta e Destino: {}, Tamanho: {}'.format(src_port, dest_port, length))
		

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

main()
