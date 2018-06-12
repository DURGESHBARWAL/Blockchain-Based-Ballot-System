import socket
from config import *

# reads from socket until "\r\n"
def read_from_socket_as_string(s):
	result = ''
	while True:
		try:
			data = s.recv(WINDOW_SIZE).decode(SOCKET_ENCTYPE)
			if data[-2:] == '\r\n':
				result += data[:-2]
				return result
			result += data
		except socket.error:
			return None

# sends all on socket, adding "\r\n"
def send_to_socket_as_string(s, msg):
	s.sendall((msg + '\r\n').encode(SOCKET_ENCTYPE))
	
# reads from socket until "\x00"
def read_from_socket_as_bytes(s):
	result = b''
	while True:
		try:
			data = s.recv(WINDOW_SIZE)
			if data[-1:] == b'\x00':
				result += data[:-1]
				return result
			result += data
		except socket.error:
			return None

# sends all on socket, adding "\00"
def send_to_socket_as_bytes(s, b_msg):
	s.sendall(b_msg + b'\00')
