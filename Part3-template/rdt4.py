#!/usr/bin/python3
"""Implementation of RDT4.0

functions: rdt_network_init, rdt_socket(), rdt_bind(), rdt_peer()
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
import math

#some constants
PAYLOAD = 1000		#size of data payload of each packet
CPORT = 100			#Client port number - Change to your port number
SPORT = 200			#Server port number - Change to your port number
TIMEOUT = 0.05		#retransmission timeout duration
TWAIT = 10*TIMEOUT 	#TimeWait duration

#store peer address info
__peeraddr = ()		#set by rdt_peer()
#define the error rates and window size
__LOSS_RATE = 0.0	#set by rdt_network_init()
__ERR_RATE = 0.0
__W = 1

# extra constant
__temp = []
__next_seq = 0  # Next sequence number for sender (initially 0)
__exp_seq = 0  # Expected sequence number for receiver (initially 0)
SN = 0  # Sender number
PN = 1  # packets to be sent


# extra function
def __unpack(packet):
    """an extra function to unpack packet"""
    size = struct.calcsize('BBHH')
    (type_num, seq_num, checksum, payload_len), data = struct.unpack('BBHH', packet[:size]), packet[size:]
    return (type_num, seq_num, checksum, socket.ntohs(payload_len)), data 



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
		#Simulate packet loss
		drop = random.random()
		if drop < __LOSS_RATE:
			#simulate packet loss of unreliable send
			print("WARNING: udt_send: Packet lost in unreliable layer!!")
			return len(byte_msg)

		#Simulate packet corruption
		corrupt = random.random()
		if corrupt < __ERR_RATE:
			err_bytearr = bytearray(byte_msg)
			pos = random.randint(0,len(byte_msg)-1)
			val = err_bytearr[pos]
			if val > 1:
				err_bytearr[pos] -= 2
			else:
				err_bytearr[pos] = 254
			err_msg = bytes(err_bytearr)
			print("WARNING: udt_send: Packet corrupted in unreliable layer!!")
			return sockd.sendto(err_msg, peer_addr)
		else:
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

def rdt_network_init(drop_rate, err_rate, W):
	"""Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability, packet corruption probability and Window size
	"""
	random.seed()
	global __LOSS_RATE, __ERR_RATE, __W
	__LOSS_RATE = float(drop_rate)
	__ERR_RATE = float(err_rate)
	__W = int(W)
	print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE, "\tWindow size:", __W)

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

def rdt_send(sockd, byte_msg):
    """Application calls this function to transmit a message (up to
	W * PAYLOAD bytes) to the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: (1) This function will return only when it knows that the
	whole message has been successfully delivered to remote process.
	(2) Catch any known error and report to the user.
	"""
	######## Your implementation #######
    global SN, __next_seq, PN, __temp
    
    whole_msg_len = len(byte_msg)
    PN = int(math.ceil(float(len(byte_msg)) / PAYLOAD)) 
    
    snd_pkt = [None] * PN  # Packets to be sent
    first_unacked_ind = 0  # Index of the first unACKed packet
    SN = __next_seq  # Update sender base
    
    for i in range(PN):
        #message cut
        if len(byte_msg) > PAYLOAD:
            data = byte_msg[0:PAYLOAD]
            byte_msg = byte_msg[PAYLOAD:]
        else:
            data = byte_msg
            byte_msg = None
        # pack the message: Header + Payload
        msg_format = struct.Struct('BBHH')
        checksum = 0
        packet = msg_format.pack(12, __next_seq, checksum, socket.htons(len(data))) + data
        checksum = __IntChksum(bytearray(packet))
        packet = msg_format.pack(12, __next_seq, checksum, socket.htons(len(data))) + data
        snd_pkt[i] = packet
        
        # Send the packet
        try:
            sent_len = __udt_send(sockd, __peeraddr, snd_pkt[i])
        except socket.error as emsg:
            print("Socket send error: ", emsg)
            return -1
        print("rdt_send: Sent one message of size %d " % sent_len)
        
        __next_seq = (__next_seq+1)%256
    
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
                checksum2 = __IntChksum(bytearray(msg))
                if checksum2 != checksum: # if corrupted
                    if type_num == 11:
                        print("rdt_send: Recieved a corrupted packet: Type = ACK, Length = %d" % len(msg))
                    else:
                        print("rdt_send: Recieved a corrupted packet: Type = DATA, Length = %d" % len(msg))
                    continue
                
                elif type_num == 11: # is ACK
                    # check if ack is out of range
                    seqNum = seq_num
                    if seq_num < SN:
                        seqNum = seq_num+256
                    if not (seqNum >= SN and seqNum <= SN + PN - 1): #out of range
                        print("rdt_send: Recieved an unexpected ACK %d" % seq_num)
                    elif seqNum == SN + PN - 1: #the last one
                        return whole_msg_len
                    else: #within range
                        print("rdt_send: Recieved the ACK with seqNo: %d" % seq_num)
                        first_unacked_ind = max((seq_num-SN+256)%256 + 1,first_unacked_ind)
                else: # is DATA
                    print("rdt_send: I am expecting an ACK packet, but received a DATA packet")
                    if seq_num == __exp_seq:
                        if recv_msg not in __temp:
                            __temp.append(recv_msg) #buffer it
                        try:
                            msg_format = struct.Struct('BBHH')
                            t_msg = msg_format.pack(11, __exp_seq, 0, socket.htons(0)) + b''
                            checksum = __IntChksum(bytearray(t_msg))
                            t_ack = msg_format.pack(11, __exp_seq, checksum, socket.htons(0)) + b''
                            __udt_send(sockd, __peeraddr, t_ack)
                        except socket.error as emsg:
                            print("rdt_send: Error in sending ACK to received data: " + str(emsg))
                            return -1
                        # __last_ack_no = seq_num
                        print("rdt_send: Drop the packet as I cannot it at this point")
                    else:
                        try:
                            msg_format = struct.Struct('BBHH')
                            sn = (__exp_seq+255)%256
                            t_msg = msg_format.pack(11, sn, 0, socket.htons(0)) + b''
                            checksum = __IntChksum(bytearray(t_msg))
                            t_ack = msg_format.pack(11, sn, checksum, socket.htons(0)) + b''
                            __udt_send(sockd, __peeraddr, t_ack)
                        except socket.error as emsg:
                            print("rdt_send: Error in sending ACK to received data: " + str(emsg))
                            return -1
                        print("rdt_send: Drop the packet as I cannot it at this point")
        else: # time out
            print("rdt_send: Timeout!! Retransmit the packet again")
            for i in range(first_unacked_ind, PN):
                try:
                    sent_len = __udt_send(sockd, __peeraddr, snd_pkt[i])
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
    global __temp, __exp_seq
    
    while __temp:
        recv_pkt = __temp.pop(0)
        (r_type, r_seq, r_, r_l), r_data = __unpack(recv_pkt)
        if r_seq == __exp_seq: 
            print("rdt_recv: Received expected buffer DATA of size %d" % len(recv_pkt))
            __exp_seq = (__exp_seq+1)%256
            return r_data
    
    while True: 
        try:
            recv_pkt = __udt_recv(sockd, length + 6)
        except socket.error as emsg:
            print("rdt_recv(): Socket receive error: " + str(emsg))
            return b''
            
        msg_format = struct.Struct('BBHH')
        (r_type, r_seq, r_check, r_l), r_data = __unpack(recv_pkt)
        t_msg = msg_format.pack(r_type, r_seq, 0, socket.htons(r_l)) + r_data
        checksum = __IntChksum(bytearray(t_msg))
        
        # recieve expected DATA and not currpted
        if checksum == r_check and r_seq == __exp_seq and r_type == 12:
            print("rdt_recv: Got an expected packet")
            try:
                ack_msg = msg_format.pack(11, r_seq, 0, socket.htons(0)) + b''
                cks = __IntChksum(bytearray(ack_msg))
                ack_msg = msg_format.pack(11, r_seq, cks, socket.htons(0)) + b''
                __udt_send(sockd, __peeraddr, ack_msg)
            except socket.error as emsg:
                print("rdt_recv: ACK error: " + str(emsg))
                return b''
            print("rdt_recv: Received a message of size %d" % len(r_data))
            __exp_seq = (__exp_seq+1)%256
            return r_data
        
        # recieve uncorrupted DATA but not expected seq num
        elif checksum == r_check and r_seq != __exp_seq and r_type == 12:
            print("rdt_recv: Got an unexpected packet")
            oldNum = (__exp_seq+255)%256
            ack_msg = msg_format.pack(11, oldNum, 0, socket.htons(0)) + b''
            ack_checksum = __IntChksum(ack_msg)
            old_ack = msg_format.pack(11, oldNum, ack_checksum, socket.htons(0)) + b''
            try:
                __udt_send(sockd, __peeraddr, old_ack)
            except socket.error as emsg:
                print("rdt_recv: ACK error: "+ str(emsg))
                return b''
            print("rdt_recv: Retransmit the ACK packet")
        
        # corrupted DATA
        elif checksum != r_check and r_type == 12:
            print("rdt_recv: Recieved a corrupted packet: Type = DATA")
            continue
        # corrupted ACK
        elif checksum != r_check and r_type == 11:
            print("rdt_recv: Recieved a corrupted packet: Type = ACK")
            continue
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
    r_list = [sockd]
    
    while True: #timer
        r, o, i = select.select(r_list, [], [], TWAIT)
        if r:
            for sock in r:
                try:
                    recv_pkt = __udt_recv(sock, PAYLOAD + 6)
                except socket.error as emsg:
                    print("rdt_close: __udt_recv error: ", emsg)
                (r_type, r_seq, r_check, r_l), r_data = __unpack(recv_pkt)
                t_msg = struct.Struct('BBHH').pack(r_type, r_seq, 0, socket.htons(r_l)) + r_data
                checksum = __IntChksum(bytearray(t_msg))
                if checksum == r_check:
                    try:
                        ack_msg = struct.Struct('BBHH').pack(11, r_seq, 0, socket.htons(0)) + b''
                        cks = __IntChksum(ack_msg)
                        ack_msg = struct.Struct('BBHH').pack(11, r_seq, cks, socket.htons(0)) + b''
                        __udt_send(sockd, __peeraddr, ack_msg)
                    except socket.error as emsg:
                        print("rdt_close: ACK error: " + str(emsg))
                    print("rdt_close: Sent the last ACK")
        else: # time out
            print("rdt_close: Nothing happened for 0.500 second")
            try:
                sockd.close()
            except socket.error as emsg:
                print("rdt_close: Socket close error: "+ str(emsg))
            break