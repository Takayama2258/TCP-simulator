#!/usr/bin/python3
"""Implementation of RDT3.0

functions: rdt_network_init(), rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: Wang Kexin
Student No. : 3035534983
Date and version: April 4 2020
Development platform: OS X
Python version: 3.7
"""

import socket
import random
import struct


#some constants
PAYLOAD = 1000		#size of data payload of the RDT layer
CPORT = 100			#Client port number - Change to your port number
SPORT = 200			#Server port number - Change to your port number
TIMEOUT = 0.05		#retransmission timeout duration
TWAIT = 10*TIMEOUT 	#TimeWait duration
seqnum = 0       #initializing states to check for duplicacy
seqnum2 = 0

#store peer address info
__peeraddr = ()		#set by rdt_peer()
#define the error rates
__LOSS_RATE = 0.0	#set by rdt_network_init()
__ERR_RATE = 0.0

#internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
	"""This function is for simulating packet loss or corruption in an unreliable channel.

	Input arguments: Unix socket object, peer address 2-tuple and the message
	Return  -> size of data sent, -1 on error
	Note: it does not catch any exception
	"""
	global __LOSS_RATE, __ERR_RATE
	if peer_addr == ():
		print("Socket send error: Peer address not set yet")
		return -1
	else:
		loss = random.random()
		if loss < __LOSS_RATE:
			print("WARNING: udt_send: Packet lost in unreliable layer!!")
			return len(byte_msg)

		corrupt = random.random()
		if corrupt < __ERR_RATE:
			err_byte = bytearray(byte_msg)
			pos = random.randint(0,len(byte_msg)-1)
			val = err_byte[pos]
			if val > 1:
				err_byte[pos] -= 2
			else:
				err_byte[pos] = 254
			err_msg = bytes(err_byte)
			print("WARNING: udt_send: Packet corrupted in unreliable layer!!")
			return sockd.sendto(err_msg, peer_addr)
		return sockd.sendto(byte_msg, peer_addr)

def __udt_recv(sockd, length):
	"""Retrieve message from underlying layer

	Input arguments: Unix socket object and the max amount of data to be received
	Return  -> the received bytes message object
	Note: it does not catch any exception
	"""
	(rmsg, peer) = sockd.recvfrom(length)
	return rmsg

def __IntChksum(byte_msg):
	"""Implement the Internet Checksum algorithm

	Input argument: the bytes message object
	Return  -> 16-bit checksum value
	Note: it does not check whether the input object is a bytes object
	"""
	total = 0
	length = len(byte_msg)	#length of the byte message object
	i = 0
	while length > 1:
		total += ((byte_msg[i+1] << 8) & 0xFF00) + ((byte_msg[i]) & 0xFF)
		i += 2
		length -= 2

	if length > 0:
		total += (byte_msg[i] & 0xFF)

	while (total >> 16) > 0:
		total = (total & 0xFFFF) + (total >> 16)

	total = ~total

	return total & 0xFFFF


#These are the functions used by appliation

def rdt_network_init(drop_rate, err_rate):
	"""Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability and packet corruption probability
	"""
	random.seed()
	global __LOSS_RATE, __ERR_RATE
	__LOSS_RATE = float(drop_rate)
	__ERR_RATE = float(err_rate)
	print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE)


def rdt_socket():
	"""Application calls this function to create the RDT socket.

	Null input.
	Return the Unix socket object on success, None on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	try:
		sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as emsg:
		print("Socket creation error: ", emsg)
		return None
	return sc


def rdt_bind(sockd, port):
	"""Application calls this function to specify the port number
	used by itself and assigns them to the RDT socket.

	Input arguments: RDT socket object and port number
	Return	-> 0 on success, -1 on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	try:
		sockd.bind(("", port))
	except socket.error as emsg:
		print("Socket bind error: ", emsg)
		return -1
	return 0



def rdt_peer(peer_ip, port):
	"""Application calls this function to specify the IP address
	and port number used by remote peer process.

	Input arguments: peer's IP address and port number
	"""
	######## Your implementation #######
	global __peeraddr
	__peeraddr = (peer_ip, port)

def __unpack(msg):
    """Helper function to unpack msg."""
    message_format = struct.Struct('BBHH')
    size = struct.calcsize(message_format)
    (msg_type, seq_num, recv_checksum, payload_len), payload = struct.unpack(message_format, msg[:size]), msg[size:]
    return (msg_type, seq_num, recv_checksum, socket.ntohs(payload_len)), payload 



def rdt_send(sockd, byte_msg):
	"""Application calls this function to transmit a message to
	the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: Make sure the data sent is not longer than the maximum PAYLOAD
	length. Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global PAYLOAD, __peeraddr, seqnum, TIMEOUT
	checksum = 0
	type_no = 12
	
	# assemble the packet header
	if (len(byte_msg) > PAYLOAD):
		data = byte_msg[0:PAYLOAD]
	else:
		data = byte_msg
	payload_len = socket.htons(len(data))
	message_format = struct.Struct('BBHH')
	msg = message_format.pack(type_no,seqnum,checksum,payload_len)+data
	checksum = __IntChksum(msg)
	msg = message_format.pack(type_no,seqnum,checksum,payload_len)+data

	while True:
		try:
			sent_len = __udt_send(sockd, __peeraddr, msg)
		except socket.error as emsg:
			print("Socket send error: ", emsg)
			return -1
		length = sent_len-6
		print("rdt_send: Sent one message of size %d" % length)
		sockd.settimeout(TIMEOUT)

		#waiting ack
		try:
			rmsg = __udt_recv(sockd, len(data)+6)
		except socket.timeout:
			print("rdt_send: Timeout!! Retransmit the packet %d again" % seqnum)
			sockd.settimeout(None)
			continue
		except socket.error as emsg:
			print("__udt_recv error: ", emsg)#print("rdt_recv: Received a message of size %d" % len(rmsg))
		sockd.settimeout(None)
		if __IntChksum(rmsg) != 0x0:
			print("rdt_send: Recieved a corrupted packet: Type = DATA, Length = %d" % len(rmsg))
			continue

		(type_id,sq_num,checksum,payload_len),data = __unpack(rmsg)
		
		if type_id == 11:
			print("rdt_send: Recieved the expected ACK")
			if sq_num == seqnum: 
				seqnum = 1-seqnum
				return length
			else:
				continue # if state is different, retransmit packet
		else:
			print("rdt_send: I am expecting an ACK packet, but received a DATA packet")
			# print("rdt_send: Retransmit %d packet again" % seqnum)

	

def rdt_recv(sockd, length):
	"""Application calls this function to wait for a message from the
	remote peer; the caller will be blocked waiting for the arrival of
	the message. Upon receiving a message from the underlying UDT layer,
    the function returns immediately.

	Input arguments: RDT socket object and the size of the message to
	received.
	Return  -> the received bytes message object on success, b'' on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global PAYLOAD, __peeraddr,seqnum2
	while True:
		try:
			rmsg = __udt_recv(sockd,length+6)
		except socket.error as emsg:
			print("Socket recv error: ", emsg)
		print("rdt_recv: Received a message of size %d" % len(rmsg))
		# length = len(rmsg)-6
		message_format = struct.Struct('BBHH')
		(type_id,sq_num,checksum,payload_len), data = __unpack(rmsg)
		if __IntChksum(rmsg) != 0x0:
			print("rdt_rcv: Recieved a corrupted packet: Type = DATA, Length = %d" % len(rmsg))
			print("rdt_rcv: Drop the packet")
			type_id = 11
			sq_num = 1-seqnum2

			checksum = 0
			ack = message_format.pack(type_id,sq_num,checksum,payload_len)
			checksum = __IntChksum(ack)
			ack = message_format.pack(type_id,sq_num,checksum,payload_len)
			try:
				length_ack = __udt_send(sockd, __peeraddr, ack)
			except socket.error as emsg:
				print("Socket send error: ", emsg)
				return b''
            #print("rdt_send: Sent one message of size %d" % length_ack)
			continue
		if type_id == 12:
			print("rdt_rcv: Got an expected Packet")
			if sq_num == seqnum2:
				type_id = 11
				checksum = 0
				ack = message_format.pack(type_id,sq_num,checksum,payload_len)
				chk_sum = __IntChksum(ack)
				ack = message_format.pack(type_id,sq_num,checksum,payload_len)
				try:
					length_ack = __udt_send(sockd, __peeraddr, ack) #send ack for recieveing pack succesfully
				except socket.error as emsg:
					print("Socket send error: ", emsg)
					return b''
				#print("rdt_send: Sent one message of size %d" % length_ack)
				seqnum2 = 1-seqnum2
				return data # return the msg content to file for it to be written in the save file
			else:
				type_id = 11
				checksum = 0
				ack = message_format.pack(type_id,sq_num,checksum,payload_len)
				chk_sum = __IntChksum(ack)
				ack = message_format.pack(type_id,sq_num,chk_sum,payload_len)
				try:
					length_ack = __udt_send(sockd, __peeraddr, ack) # if incorrect state, send ack to tell client to resend the packet
				except socket.error as emsg:
					print("Socket send error: ", emsg)
					return b''
				print("rdt_send: Sent one message of size %d" % length_ack)
		else:
			continue


def rdt_close(sockd):
	"""Application calls this function to close the RDT socket.

	Input argument: RDT socket object

	Note: (1) Catch any known error and report to the user.
	(2) Before closing the RDT socket, the reliable layer needs to wait for TWAIT
	time units before closing the socket.
	"""
	######## Your implementation #######
	global PAYLOAD, __peeraddr
	sockd.settimeout(TWAIT) # start timer
	try:
		rmsg = __udt_recv(sockd, 1000+6)
	except socket.timeout: # if timeout happens close the socket
		try:
			print("rdt_close: Nothing happened for 0.500 second")
			sockd.close()
			print("rdt_close: Release the socket")
			return
		except socket.error as emsg:
			print("Socket close error: ", emsg)
	except socket.error as emsg:
		print("Socket recv error: ", emsg)
	print("rdt_recv: Received a message of size %d" % len(rmsg))
	strct = 'BBHH'+ str(len(rmsg)-6)+'s'
	message_format = struct.Struct(strct)
	(type_id,sq_num, chk_sum,payload_len, msg) = message_format.unpack(rmsg) # if a packet is recevied then un pack it
	if type_id == 12: # check if packet contains data
		sockd.settimeout(None)#print("recieving last packet")
		type_id = 11
		chk_sum = 0
		message_format2 = struct.Struct('BBHH')
		ACK = message_format2.pack(type_id,sq_num, chk_sum,payload_len)
		chk_sum = __IntChksum(ACK)
		ACK = message_format2.pack(type_id,sq_num, chk_sum,payload_len)
		try:
			length = __udt_send(sockd, __peeraddr, ACK) # if yes then send last ack for the last data packet
		except socket.error as emsg:
			print("Socket send error: ", emsg)
			return -1
		print("rdt_send: Sent one message of size %d" % length)
	sockd.settimeout(None) # stop the timer
