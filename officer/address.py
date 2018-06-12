import socket
from config import *

def inrange(c, a, b):
	# is c in [a,b)?, if a == b then it assumes a full circle
	# on the DHT, so it returns True.
	a = a % SIZE
	b = b % SIZE
	c = c % SIZE
	if a < b:
		return a <= c and c < b
	return a <= c or c < b
	
def getId(addr, port):
	validateAddr(addr)
	validatePort(port)
	_hash = ID_HASHALGO((addr + ":" + str(port)).encode(ID_ENCTYPE)).hexdigest()
	_id = int(_hash, 16)
	return _hash, _id
	
def validateAddress(addr):
	if not isinstance(addr, Address):
		raise TypeError('Local address should be a instance of address.Address class')
		
def validateAddr(addr):
	try:
		socket.inet_aton(addr)
	except:
		raise Exception('Invalid ip address, given {}'.format(addr))

def validatePort(port):
	if not isinstance(port, int):
		raise TypeError('Port should be a instance of int class')
	if port < 1024 or port > 65535:
		raise Exception('Port should be in the range [1024:65536)')
	
class Address:
	def __init__(self, addr, port):
		self._hash, self._id = getId(addr, port)
		self._addr = addr
		self._port = port
			
	@property
	def hash(self):
		return self._hash
	
	@property
	def addr(self):
		return self._addr
		
	@property
	def port(self):
		return self._port
		
	def id(self, offset = 0):
		return (self._id + offset) % SIZE
		
	def __lt__(self, other):
		return other.id() < self.id()
	
	def __le__(self, other):
		return other.id() <= self.id()
	
	def __gt__(self, other):
		return other.id() > self.id()
	
	def __ge__(self, other):
		return other.id() >= self.id()
		
	def __eq__(self, other):
		return other.id() == self.id()
