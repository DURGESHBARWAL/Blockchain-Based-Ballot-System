import time, threading, address, sys, remote, random, socket, network, json, rsa, aesHmac, Crypto.Util.number as crypto_number
from config import *

def repeatAndSleep(sleep_time):
	def inside(func):
		def insideInside(self, *args, **kwargs):
			self._shutdownMutex.acquire()
			shutdown_status = self._shutdown
			mutexReleaser(self._shutdownMutex)
			while not shutdown_status:
				ret = func(self, *args, **kwargs)
				if not ret:
					return
				time.sleep(sleep_time)
				self._shutdownMutex.acquire()
				shutdown_status = self._shutdown
				mutexReleaser(self._shutdownMutex)
		return insideInside
	return inside

def retryOnSocketError(retry_limit):
	def decorator(func):
		def inner(self, *args, **kwargs):
			retry_count = 0
			self._shutdownMutex.acquire()
			shutdown_status = self._shutdown
			mutexReleaser(self._shutdownMutex)
			while retry_count < retry_limit and not shutdown_status:
				try:
					ret = func(self, *args, **kwargs)
					return ret
				except socket.error:
					time.sleep(retry_count)
					retry_count += 1
				self._shutdownMutex.acquire()
				shutdown_status = self._shutdown
				mutexReleaser(self._shutdownMutex)
			if retry_count == retry_limit:
				self._shutdown = True
				sys.exit(-1)
		return inner
	return decorator
	
def mutexReleaser(f):
	try:
		f.release()
	except:
		pass

class Node:
	def __init__(self, key, localAddress, hostAddress = None, bits = RSA_BITS):
		address.validateAddress(localAddress)
		self._address = localAddress
		
		try:
			self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self._socket.bind((self._address.addr, self._address.port))
			self._socket.close()
		except:
			raise Exception('local address already in use ({}:{})'.format(localAddress.addr, localAddress.port))
		
		if hostAddress:
			address.validateAddress(hostAddress)
			
		self._path = '{}\\{}.rsa.keys'.format(localAddress.hash, bits)
		try:
			self._e, self._d = json.loads(aesHmac.readEncryptedFile(self._path, key))[-1]
		except FileNotFoundError:
			keys = rsa.newKeys(RSA_BITS)
			aesHmac.writeEncryptedFile(self._path, json.dumps([keys]), key)
			self._e, self._d = keys
			
		self._keysMutex = threading.BoundedSemaphore()
		self._shutdownMutex = threading.BoundedSemaphore()
		
		self._shutdown = False
		self._daemons = {}
		self._succ = []
		self._commands = {}
		
		if not self.join(hostAddress):
			raise Exception('host address not found, connection refused')
		
	def __del__(self):
		self.shutdown()
			
	def getKeys(self):
		self._keysMutex.acquire()
		ret = self._e, self._d
		mutexReleaser(self._keysMutex)
		return ret
	
	def updateKeys(self, key, bits = RSA_BITS):
		try:
			key_set = json.loads(aesHmac.readEncryptedFile(self._path, key))
			keys = rsa.newKeys(bits)
			self._keysMutex.acquire()
			self._e, self._d = keys
			mutexReleaser(self._keysMutex)
			key_set.append(keys)
			aesHmac.writeEncryptedFile(self._path, json.dumps(key_set), key)
			return True
		except:
			return False
			
	def isOurs(self, id):
		assert id >= 0 and id < SIZE
		return address.inrange(id, self._pred.id(1), self.id(1))
		
	def isMe(self, i):
		return i and i.addr == self.addr and i.port == self.port
		
	def getNeighbours(self):
		A = {}
		lists = self._finger + self._succ + [self._pred]
		for i in lists:
			if i and not self.isMe(i) and i.ping():
				a = (i.addr, i.port)
				if not (a in A):
					A[a] = i
		return A

	def shutdown(self):
		try:
			mutexReleaser(self._shutdownMutex)
			mutexReleaser(self._keysMutex)
			self._shutdownMutex.acquire()
			self._shutdown = True
			mutexReleaser(self._shutdownMutex)
		except:
			pass
		try:
			try:
				self._socket.shutdown(socket.SHUT_RDWR)
				self._socket.close()
			except socket.error:
				pass
			for v in self._finger:
				if v and not self.isMe(v):
					v.shutdown()
			for v in self._succ:
				if v and not self.isMe(v):
					v.shutdown()
			v = self._pred
			if v and not self.isMe(v):
				v.shutdown()
		except:
			pass
		self._socket = None
		
	@property
	def addr(self):
		return self._address.addr
		
	@property
	def port(self):
		return self._address.port
		
	@property
	def hash(self):
		return self._address.hash
		
	def id(self, offset = 0):
		return self._address.id(offset)
		
	def start(self):
		self._daemons['run'] = threading.Thread(target = self.run)
		self._daemons['fix_fingers'] = threading.Thread(target = self.fixFingers)
		self._daemons['stabilize'] = threading.Thread(target = self.stabilize)
		self._daemons['update_successors'] = threading.Thread(target = self.updateSuccessors)
		for k, v in self._daemons.items():
			v.daemon = True 
			v.start()
		
	def ping(self):
		return True
		
	def join(self, hostAddress = None):
		self._finger = [None] * LOGSIZE
		self._pred = None
		if hostAddress:
			address.validateAddress(hostAddress)
			self._finger[0] = remote.Remote(hostAddress, self).findSuccessor(self.id())
			if self._finger[0] == None:
				return False
		else:
			self._finger[0] = self
		return True
			
	@repeatAndSleep(STABILIZE_INT)
	@retryOnSocketError(STABILIZE_RET)
	def stabilize(self, ret = True):
		suc = self.successor()
		if suc.id() != self._finger[0].id():
			self._finger[0] = suc
		x = suc.predecessor()
		if x != None and \
		   address.inrange(x.id(), self.id(1), suc.id()) and \
		   self.id(1) != suc.id() and \
		   x.ping():
			self._finger[0] = x
		self.successor().notify(self)
		return ret

	def notify(self, remote):
		if self.predecessor() == None or \
		   address.inrange(remote.id(), self.predecessor().id(1), self.id()) or \
		   not self.predecessor().ping():
			self._pred = remote

	@repeatAndSleep(FIX_FINGERS_INT)
	def fixFingers(self, ret = True):
		i = random.randrange(LOGSIZE - 1) + 1
		self._finger[i] = self.findSuccessor(self.id(1 << i))
		return ret

	@repeatAndSleep(UPDATE_SUCCESSORS_INT)
	@retryOnSocketError(UPDATE_SUCCESSORS_RET)
	def updateSuccessors(self, ret = True):
		suc = self.successor()
		if suc.id() != self.id():
			successors = [suc]
			suc_list = suc.getSuccessors()
			if suc_list:
				for i in suc_list:
					successors.append(remote.Remote(address.Address(i[0], i[1]), self))
			self._succ = successors
		return ret

	def getSuccessors(self):
		A = []
		for i in self._succ[:N_SUCCESSORS - 1]:
			A.append((i._address.addr, i._address.port))
		return A
		
	def successor(self):
		lists = [self._finger[0]] + self._succ
		for remote in lists:
			if remote and remote.ping():
				self._finger[0] = remote
				return remote
		self._shutdown = True
		sys.exit(-1)

	def predecessor(self):
		return self._pred

	@retryOnSocketError(FIND_SUCCESSOR_RET)
	def findSuccessor(self, id):
		if self.predecessor() and self.isOurs(id):
			return self
		node = self.findPredecessor(id)
		return node.successor() if node else node

	@retryOnSocketError(FIND_PREDECESSOR_RET)
	def findPredecessor(self, id):
		node = self
		if node.successor().id() == node.id():
			return node
		try:
			while node and not address.inrange(id, node.id(1), node.successor().id(1)):
				node = node.closestPrecedingFinger(id)
			return node
		except:
			pass

	def closestPrecedingFinger(self, id):
		lists = self._succ + self._finger
		for remote in reversed(lists):
			if remote != None and address.inrange(remote.id(), self.id(1), id) and remote.ping():
				return remote
		return self
		
	def command(self, cmd, id = None):
		if not id:
			suc = self.successor()
			return suc.command(cmd) if not self.isMe(suc) else None
		else:
			suc = self.findSuccessor(id)
			return suc.command(cmd) if suc != None and not self.isMe(suc) and suc.id() == id else None
		
	def reply(self, args):
		try:
			conn, addr = args

			b = crypto_number.getRandomInteger(DIFFIE_HELLMEN_KEY_SIZE) % N
					
			A = network.read_from_socket_as_string(conn)
		
			if A:
				A = json.loads(A)
			
				if type(A) != dict:
					raise Exception
			
				sig = A.pop('sig')
				if not rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
					raise Exception
			
				ga_modn = A['key']
			
				pk, sk = self.getKeys()
			
				A = {
					'key': pow(G, b, N),
					'public key': pk
				}
			
				A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
			
				network.send_to_socket_as_string(conn, json.dumps(A))
			
				gab_modn = pow(ga_modn, b, N)
			
				request = network.read_from_socket_as_bytes(conn)
			
				if request:		
							
					request = aesHmac.symmDecryption(request, gab_modn)
				
					command = request.split(' ')[0]
				
					request = request[len(command) + 1:]

					result = json.dumps("")
				
					if command == 'get_successor':
						successor = self.successor()
						result = json.dumps((successor.addr, successor.port))
					elif command == 'get_predecessor':
						if self._pred != None:
							predecessor = self.predecessor()
							result = json.dumps((predecessor.addr, predecessor.port))
					elif command == 'find_successor':
						successor = self.findSuccessor(int(request))
						result = json.dumps((successor.addr, successor.port))
					elif command == 'closest_preceding_finger':
						closest = self.closestPrecedingFinger(int(request))
						result = json.dumps((closest.addr, closest.port))
					elif command == 'notify':
						npredecessor = address.Address(request.split(' ')[0], int(request.split(' ')[1]))
						self.notify(remote.Remote(npredecessor, self))
					elif command == 'get_successors':
						result = json.dumps(self.getSuccessors())
					else:
						try:
							t = self._commands[command]
							def f(A):
								network.send_to_socket_as_bytes(conn, aesHmac.symmEncryption(A, gab_modn))
							t(request, f)
							conn.close()
							return
						except KeyError:
							pass
						
					network.send_to_socket_as_bytes(conn, aesHmac.symmEncryption(result, gab_modn))
		except:
			pass
		conn.close()

	def run(self):
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._socket.bind((self._address.addr, self._address.port))
		self._socket.listen(LISTEN_LIMIT)
		self._shutdownMutex.acquire()
		shutdown_status = self._shutdown
		mutexReleaser(self._shutdownMutex)
		while not shutdown_status:
			try:
				client = self._socket.accept()
			except socket.error:
				self._shutdownMutex.acquire()
				self._shutdown = True
				mutexReleaser(self._shutdownMutex)
				return
			recv_thread = threading.Thread(target = self.reply, args = (client,))
			recv_thread.daemon = True
			recv_thread.start()
			self._shutdownMutex.acquire()
			shutdown_status = self._shutdown
			mutexReleaser(self._shutdownMutex)
							
	def registerCommand(self, cmd, func):
		self._commands[cmd] = func
		
	def unregisterCommand(self, cmd):
		try:
			del self._commands[cmd]
			return True
		except KeyError:
			return False
