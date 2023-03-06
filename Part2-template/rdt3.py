#!/usr/bin/python3
"""Implementation of RDT3.0

functions: rdt_network_init(), rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: Wang Kexin
Student No. : 3035534983
Date and version: April 5 2020 V-2.0
Development platform: OS X
Python version: 3.7
"""

import socket
import random
import struct
import select

# some constants
PAYLOAD = 1000  	# size of data payload of the RDT layer
CPORT = 100  	# Client port number - Change to your port number
SPORT = 200  	# Server port number - Change to your port number
TIMEOUT = 0.05 	 	# retransmission timeout duration
TWAIT = 10 * TIMEOUT  # TimeWait duration

# store peer address info
__peeraddr = ()  # set by rdt_peer()
# define the error rates
__LOSS_RATE = 0.0  # set by rdt_network_init()
__ERR_RATE = 0.0

# extra constant
__temp = []
__send_seq = 0
__recv_seq = 0
__last_ack_no = None


# internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
    """This function is for simulating packet loss or corruption in an unreliable channel.

    Input arguments: Unix socket object, peer address 2-tuple and the message
    Return  -> size of data sent, -1 on error
    Note: it does not catch any exception
    """
    global __LOSS_RATE, __ERR_RATE
    if peer_addr == ():
        print("__udt_send error: No peer address!")
        return -1
    else:
        # packet loss
        drop = random.random()
        if drop < __LOSS_RATE:
            print("WARNING: Packet lost in unreliable layer!!")
            return len(byte_msg)

        # packet corruption
        corrupt = random.random()
        if corrupt < __ERR_RATE:
            err_bytearr = bytearray(byte_msg)
            pos = random.randint(0, len(byte_msg) - 1)
            val = err_bytearr[pos]
            if val > 1:
                err_bytearr[pos] -= 2
            else:
                err_bytearr[pos] = 254
            err_msg = bytes(err_bytearr)
            print("WARNING: Packet corrupted in unreliable layer!!")
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


def __int_chksum(byte_msg):
    """Implement the Internet Checksum algorithm

    Input argument: the bytes message object
    Return  -> 16-bit checksum value
    Note: it does not check whether the input object is a bytes object
    """
    total = 0
    length = len(byte_msg)  # length of the byte message object
    i = 0
    while length > 1:
        total += ((byte_msg[i + 1] << 8) & 0xFF00) + ((byte_msg[i]) & 0xFF)
        i += 2
        length -= 2

    if length > 0:
        total += (byte_msg[i] & 0xFF)

    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)

    total = ~total

    return total & 0xFFFF


# These are the functions used by application

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as err_msg:
        print("Socket creation error: ", err_msg)
        return None
    return sock


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
    except socket.error as err_msg:
        print("Socket bind error: ", err_msg)
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


def __unpack(packet):
    """an extra function to unpack packet"""
    size = struct.calcsize('BBHH')
    (type_num, seq_num, checksum, payload_len), data = struct.unpack('BBHH', packet[:size]), packet[size:]
    return (type_num, seq_num, checksum, socket.ntohs(payload_len)), data 


def rdt_send(sockd, byte_msg):
	"""Application calls this function to transmit a message to
    the remote peer through the RDT socket.

    Input arguments: RDT socket object and the message bytes object
    Return  -> size of data sent on success, -1 on error

    Note: Make sure the data sent is not longer than the maximum PAYLOAD
    length. Catch any known error and report to the user.
    """
	######## Your implementation #######
	global PAYLOAD, __peeraddr, __temp, __send_seq, __last_ack_no
	
	if len(byte_msg) > PAYLOAD:
		msg = byte_msg[0:PAYLOAD]
	else:
		msg = byte_msg
	
	# pack the message: Header + Payload
	msg_format = struct.Struct('BBHH')
	checksum = 0
	packet = msg_format.pack(12, __send_seq, checksum, socket.htons(len(msg))) + msg
	checksum = __int_chksum(bytearray(packet))
	packet = msg_format.pack(12, __send_seq, checksum, socket.htons(len(msg))) + msg
    
	try:
		sent_len = __udt_send(sockd, __peeraddr, packet)
	except socket.error as emsg:
		print("Socket send error: ", emsg)
		return -1
	print("rdt_send: Sent one message of size %d " % sent_len)


	socket_list = [sockd] 
	while True: 
		# set timer
		r_list, o, i = select.select(socket_list, [], [], TIMEOUT)
		if r_list: 
			for sock in r_list:
				try:
					recv_msg = __udt_recv(sock, PAYLOAD + 6)
				except socket.error as emsg:
					print("__udt_recv error: ", emsg)
					return -1
                
				(type_num, seq_num, checksum, payload_len), data = __unpack(recv_msg)
				msg = struct.Struct('BBHH').pack(type_num, seq_num, 0, socket.htons(payload_len)) + data
				checksum2 = __int_chksum(bytearray(msg))
				# if corrupted
				if checksum2 != checksum:
					print("rdt_send: Recieved a corrupted packet: Type = DATA, Length = %d" % len(msg))
					continue
				# if not expected ACK 
				elif type_num == 11 and seq_num == 1 - __send_seq:
					print("rdt_send: Recieved an unexpected ACK %d" % seq_num)
					continue
                # if correct ack
				elif type_num == 11 and seq_num == __send_seq:
					print("rdt_send: Recieved the expected ACK")
					__send_seq = 1-__send_seq  
					return sent_len - 6 
				else: # if DATA
					print("rdt_send: I am expecting an ACK packet, but received a DATA packet")
					if recv_msg not in __temp: 
						__temp.append(recv_msg) #buffer it
					try:
						t_msg = msg_format.pack(11, seq_num, 0, socket.htons(0)) + b''
						checksum = __int_chksum(bytearray(t_msg))
						t_ack = msg_format.pack(11, seq_num, checksum, socket.htons(0)) + b''
						__udt_send(sockd, __peeraddr, t_ack)
					except socket.error as emsg:
						print("rdt_send: Error in sending ACK to received data: " + str(emsg))
						return -1
					__last_ack_no = seq_num
					print("rdt_send: Drop the packet as I cannot it at this point")
					continue
		# time out
		else: 
			print("rdt_send: Timeout!! Retransmit the packet %d again" % __send_seq)
			try:
				sent_len = __udt_send(sockd, __peeraddr, packet)
			except socket.error as emsg:
				print("Socket send error: ", emsg)
				return -1
			print("rdt_send: Resent one message of size %d " % sent_len)


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
	global __peeraddr, __temp, __recv_seq, __last_ack_no
	
	while __temp:
		recv_pkt = __temp.pop(0)
		(r_type, r_seq, r_, r_l), r_data = __unpack(recv_pkt)
		if r_seq == __recv_seq: 
			print("rdt_recv: Received expected buffer DATA of size %d" % len(recv_pkt))
			__recv_seq = 1- __recv_seq 
			return r_data
			
	while True: 
		try:
			recv_pkt = __udt_recv(sockd, length + 6)
		except socket.error as err_msg:
			print("rdt_recv(): Socket receive error: " + str(err_msg))
			return b''

		msg_format = struct.Struct('BBHH')
		(r_type, r_seq, r_check, r_l), r_data = __unpack(recv_pkt)
		t_msg = msg_format.pack(r_type, r_seq, 0, socket.htons(r_l)) + r_data
		checksum = __int_chksum(bytearray(t_msg))
		# recieve expected DATA
		if checksum == r_check and r_seq == __recv_seq and r_type == 12:
			print("rdt_recv: Got an expected packet")
			try:
				ack_msg = msg_format.pack(11, r_seq, 0, socket.htons(0)) + b''
				cks = __int_chksum(bytearray(ack_msg))
				ack_msg = msg_format.pack(11, r_seq, cks, socket.htons(0)) + b''
				__udt_send(sockd, __peeraddr, ack_msg)
			except socket.error as emsg:
				print("rdt_recv: ACK error: " + str(emsg))
				return b''
			print("rdt_recv: Received a message of size %d" % len(r_data))
			__last_ack_no = __recv_seq
			__recv_seq = 1 -__recv_seq 
			return r_data
		# DATA corrupted
		elif checksum != r_check and r_type == 12:
			print("rdt_recv: Recieved a corrupted packet: Type = DATA, Length = %d" % len(r_data))
			# continue
			ack_msg = msg_format.pack(11, 1-__recv_seq, 0, socket.htons(0)) + b''
			ack_checksum = __int_chksum(ack_msg)
			old_ack = msg_format.pack(11, 1-__recv_seq, ack_checksum, socket.htons(0)) + b''
			try:
				__udt_send(sockd, __peeraddr, old_ack)
			except socket.error as emsg:
				print("rdt_recv: ACK error: "+ str(emsg))
				return b''
			__last_ack_no=1-__recv_seq
			print("rdt_recv: Retransmit the ACK packet")
		# DATA seq num not correct
		elif r_seq == 1-__recv_seq and r_type == 12:
			print("rdt_recv: Got an unexpected packet")
			ack_msg = msg_format.pack(11, 1-__recv_seq, 0, socket.htons(0)) + b''
			ack_checksum = __int_chksum(ack_msg)
			old_ack = msg_format.pack(11, 1-__recv_seq, ack_checksum, socket.htons(0)) + b''
			try:
				__udt_send(sockd, __peeraddr, old_ack)
			except socket.error as emsg:
				print("rdt_recv: ACK error: "+ str(emsg))
				return b''
			__last_ack_no=1-__recv_seq
			print("rdt_recv: Retransmit the ACK packet")
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
	global __last_ack_no
	r_list = [sockd]

	while True:
		r, o, i = select.select(r_list, [], [], TWAIT)
		if r: 
			for sock in r:
				try:
					recv_pkt = __udt_recv(sock, PAYLOAD + 6)
				except socket.error as emsg:
					print("rdt_close: __udt_recv error: ", emsg)
				(r_type, r_seq, r_check, r_l), r_data = __unpack(recv_pkt)
				t_msg = struct.Struct('BBHH').pack(r_type, r_seq, 0, socket.htons(r_l)) + r_data
				checksum = __int_chksum(bytearray(t_msg))
				if checksum == r_check and r_seq == __last_ack_no:
					try:
						ack_msg = struct.Struct('BBHH').pack(11, r_seq, 0, socket.htons(0)) + b''
						cks = __int_chksum(ack_msg)
						ack_msg = struct.Struct('BBHH').pack(11, r_seq, cks, socket.htons(0)) + b''
						__udt_send(sockd, __peeraddr, ack_msg)
					except socket.error as emsg:
						print("rdt_close: ACK error: " + str(emsg))
					print("rdt_close: Sent the last ACK")
		else: 
			print("rdt_close: Nothing happened for 0.500 second")
			try:
				sockd.close()
			except socket.error as emsg:
				print("rdt_close: Socket close error: "+ str(emsg))
			break
