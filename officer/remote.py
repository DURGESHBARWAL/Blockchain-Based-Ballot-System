import threading, socket, address, network, json, random, rsa, aesHmac, Crypto.Util.number as crypto_number
from config import *

def requiresConnection(func):
	def inner(self, *args, **kwargs):
		self._shutdownMutex.acquire()
		shutdown_status = self._shutdown
		mutexReleaser(self._shutdownMutex)
		if not shutdown_status:
			try:
				self._connMutex.acquire()
				self.openConnection()
				ret = func(self, *args, **kwargs)
				self.closeConnection()
				mutexReleaser(self._connMutex)
			except:
				mutexReleaser(self._connMutex)
				return
			return ret
	return inner
	
def mutexReleaser(f):
	try:
		f.release()
	except:
		pass

class Remote:
	def __init__(self, addr, masterAddress):
		address.validateAddress(addr)
		self._address = addr
		self._masterAddress = masterAddress
		
		self._connMutex = threading.BoundedSemaphore()
		self._shutdownMutex = threading.BoundedSemaphore()
		
		self._shutdown = False
			
	@property
	def hash(self):
		return self._address.hash
		
	@property
	def addr(self):
		return self._address.addr
	
	@property
	def port(self):
		return self._address.port
		
	def id(self, offset = 0):
		return self._address.id(offset)
	
	def shutdown(self):
		mutexReleaser(self._shutdownMutex)
		mutexReleaser(self._connMutex)
		self._shutdownMutex.acquire()
		self._shutdown = True
		mutexReleaser(self._shutdownMutex)
		try:
			self.closeConnection()
		except:
			pass
		
	def symmEncryption(self, msg):
		return aesHmac.symmEncryption(msg, self._gab_modn)
		
	def symmDecryption(self, msg):
		return aesHmac.symmDecryption(msg, self._gab_modn)
		
	def sendAsString(self, string):
		network.send_to_socket_as_string(self._socket, string)
		
	def recvAsString(self):
		return network.read_from_socket_as_string(self._socket)
		
	def sendAsBytes(self, b_string):
		network.send_to_socket_as_bytes(self._socket, b_string)
		
	def recvAsBytes(self):
		return network.read_from_socket_as_bytes(self._socket) 
		
	def openConnection(self):
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.connect((self._address.addr, self._address.port))
		a = crypto_number.getRandomInteger(DIFFIE_HELLMEN_KEY_SIZE) % N
		pk, sk = self._masterAddress.getKeys()
		A = {
			'key': pow(G, a, N),
			'public key': pk
		}
		A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
		self.sendAsString(json.dumps(A))
		B = json.loads(self.recvAsString())
		if type(B) == dict:
			sig = B.pop('sig')
			if rsa.verify(sig, json.dumps(B, sort_keys = True), B['public key']):
				gb_modn = B['key']
				self._gab_modn = pow(gb_modn, a, N)
				return
		self.closeConnection()
		raise Exception
		
	def closeConnection(self):
		self._socket.shutdown(socket.SHUT_RDWR)
		self._socket.close()
		self._socket = None

	def ping(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((self.addr, self.port))
			network.send_to_socket_as_string(s, '\r\n')
			s.close()
			return True
		except socket.error:
			return False
			
	@requiresConnection
	def command(self, msg):
		msg = self.symmEncryption(msg)
		self.sendAsBytes(msg)
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		return response
		
	@requiresConnection
	def getSuccessors(self):
		self.sendAsBytes(self.symmEncryption('get_successors'))
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		response = json.loads(response)
		if not response or response == "":
			return []
		return response

	@requiresConnection
	def successor(self):
		self.sendAsBytes(self.symmEncryption('get_successor'))
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		response = json.loads(response)
		if not response or response == "":
			return None
		try:
			return Remote(address.Address(response[0], response[1]), self._masterAddress)
		except:
			return None

	@requiresConnection
	def predecessor(self):
		self.sendAsBytes(self.symmEncryption('get_predecessor'))
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		response = json.loads(response)
		if not response or response == "":
			return None
		try:
			return Remote(address.Address(response[0], response[1]), self._masterAddress)
		except:
			return None

	@requiresConnection
	def findSuccessor(self, id):
		self.sendAsBytes(self.symmEncryption('find_successor {}'.format(id)))
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		response = json.loads(response)
		if not response or response == "":
			return None
		try:
			return Remote(address.Address(response[0], response[1]), self._masterAddress)
		except:
			return None

	@requiresConnection
	def closestPrecedingFinger(self, id):
		self.sendAsBytes(self.symmEncryption('closest_preceding_finger {}'.format(id)))
		response = self.recvAsBytes()
		response = self.symmDecryption(response)
		response = json.loads(response)
		if not response or response == "":
			return None
		try:
			return Remote(address.Address(response[0], response[1]), self._masterAddress)
		except:
			return None

	@requiresConnection
	def notify(self, node):
		self.sendAsBytes(self.symmEncryption('notify {} {}'.format(node.addr, node.port)))
