import node, rsa, blockchain, json, threading, time, address, Crypto.Util.number as crypto_number, aesHmac, hashlib
from public_details import *

# Update Neighbours
UPDATE_NEIGHBOUR_INT = 2

# Update Chain
UPDATE_CHAIN_INT = 7

# Mining
MINING_INT = 3

RSA_BITS = 1024

class Node:
	def __init__(self, password, localAddress, hostAddress = None, bits = RSA_BITS):
	
		self._chainMutex = threading.BoundedSemaphore()
		self._neighboursMutex = threading.BoundedSemaphore()
		self._shutdownMutex = threading.BoundedSemaphore()
			
		self._local = node.Node(password, localAddress, hostAddress, bits)
		
		def __getChainHash(request, f):
			try:
				A = json.loads(request)
				if type(A) == dict:
					sig = A.pop('sig')
					if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
						self._chainMutex.acquire()
						A = blockchain.hash(self._chain.chain)
						node.mutexReleaser(self._chainMutex)
						pk, sk = self.getKeys()
						A = {
							'chain hash': A,
							'public key': pk
						}
						A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
						A = json.dumps(A)
						f(A)
						return
			except:
				pass
			f('NOT OK')
		self._local.registerCommand('get_chain_hash', __getChainHash)
		
		def __getChain(request, f):
			try:
				A = json.loads(request)
				if type(A) == dict:
					sig = A.pop('sig')
					if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
						self._chainMutex.acquire()
						A = dict(self._chain.__dict__)
						node.mutexReleaser(self._chainMutex)
						pk, sk = self.getKeys()
						A.pop('mineableTransactionsMutex')
						A.pop('pendingTransactionsMutex')
						A = {
							'chain': A,
							'public key': pk
						}
						A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
						A = json.dumps(A)
						f(A)
						return
			except:
				pass
			f('NOT OK')
		self._local.registerCommand('get_chain', __getChain)
		
		def __getPublicKey(request, f):
			f(json.dumps(self.getKeys()[0]))
		self._local.registerCommand('get_public_key', __getPublicKey)
		
		def __broadcastVote(request, f):
			try:
				A = json.loads(request)
				if type(A) == dict:
					sig = A.pop('sig')
					id = A.pop('id')
					if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
						A['sig'] = sig
						if not self.__validateOfficerSignatures(A):
							f('NOT OK')
							return
						self._chainMutex.acquire()
						ret = self._chain.addTransaction(A['voter'], A)
						node.mutexReleaser(self._chainMutex)
						if ret:
							A = dict(A)
							A['id'] = self.id()
							f('OK')
							self.__broadcastUtil(A, 'broadcast_vote', id)
							return
			except:
				pass
			f('NOT OK')
		self._local.registerCommand('broadcast_vote', __broadcastVote)
		
		def __broadcastBlock(request, f):
			try:
				A = json.loads(request)
				if type(A) == dict:
					sig = A.pop('sig')
					id = A.pop('id')
					if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
						A['sig'] = sig
						for k, v in A['transactions'].items():
							if not self.__validateOfficerSignatures(v):
								f('NOT OK')
								return
						self._chainMutex.acquire()
						ret = self._chain.addBlock(A)
						node.mutexReleaser(self._chainMutex)
						if ret:
							A = dict(A)
							A['id'] = self.id()
							f('OK')
							self.__broadcastUtil(A, 'broadcast_block', id)
							return
			except:
				pass
			f('NOT OK')
		self._local.registerCommand('broadcast_block', __broadcastBlock)
		
		def __verify(request, f):
			try:
				A = json.loads(request)
				if type(A) == dict:
					DB_MANAGER = ssql.SSQLiteManager('public_details.db')
					if DB_MANAGER.select('ELIGIBLE_VOTERS', cond = '"voter id" == "{}"'.format(A['voter id'])):
						DB_MANAGER.close()
						f(json.dumps(rsa.sign(A['random nonce'], self.getKeys()[1])))
						return
					DB_MANAGER.close()
			except:
				pass
			f('NOT OK')
		self._local.registerCommand('verify', __verify)
		
		self._local.start()
		
		self._isMiner = False
		
		self._shutdown = False
		
		self._neighbours = {}
		
		self._chainMutex.acquire()
		if not hostAddress:
			self._chain = blockchain.Blockchain()
		else:
			self._chain = blockchain.Blockchain(self.getChainOfId(hostAddress.id()))
		node.mutexReleaser(self._chainMutex)
		
		self._daemon = {}
		
		self._daemon['update_neighbours'] = threading.Thread(target = self.updateNeighbours)
		self._daemon['update_chain'] = threading.Thread(target = self.updateChain)
		self._daemon['sch_mining'] = threading.Thread(target = self.mine)
		
		for k, v in self._daemon.items():
			v.daemon = True
			v.start()
			
	@property		
	def addr(self):
		return self._local.addr
	
	@property
	def port(self):
		return self._local.port
	
	@property
	def hash(self):
		return self._local.hash
		
	def id(self, offset = 0):
		return self._local.id(offset)
		
	def __del__(self):
		self.shutdown()
		
	def shutdown(self):
		self.writeChain()
		try:
			node.mutexReleaser(self._shutdownMutex)
			node.mutexReleaser(self._chainMutex)
			node.mutexReleaser(self._neighboursMutex)
			self._shutdownMutex.acquire()
			self._shutdown = True
		except:
			pass
		node.mutexReleaser(self._shutdownMutex)
		#self.mine(False)
		try:
			self._local.shutdown()
		except:
			pass
		
	@node.repeatAndSleep(UPDATE_NEIGHBOUR_INT)
	def updateNeighbours(self, ret = True):
		self._neighboursMutex.acquire()
		self._neighbours = self._local.getNeighbours()
		node.mutexReleaser(self._neighboursMutex)
		return ret
		
	def getNeighbours(self):
		ret = self._neighbours
		return ret if ret else {}
		
	def getPublicKeyOfAddress(self, addr, port):
		id = address.getId(addr, port)[1]
		return self.getPublicKeyOfId(id)
		
	def getPublicKeyOfId(self, id):
		pk = self._local.command('get_public_key', id)
		if pk:
			return json.loads(pk)
	
	def toggleMiner(self):
		self._isMiner = not self._isMiner
		
	def isMiner(self):
		return self._isMiner
		
	def getChain(self):
		return self._chain
		
	def getChainOfAddress(self, addr, port):
		return self.getChainOfId(address.getId(addr, port)[1])
		
	def getChainOfId(self, id):
		pk, sk = self.getKeys()
		A = {
			'msg': 'I want your chain',
			'public key': pk,
			'timestamp': time.time()
		}
		A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
		A = 'get_chain {}'.format(json.dumps(A))
		response = self._local.command(A, id)
		if response:
			A = json.loads(response)
			if type(A) == dict:		
				sig = A.pop('sig')
				if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
					return A['chain']
		return None
		
	def getChainHashOfAddress(self, addr, port):
		return self.getChainHashOfId(address.getId(addr, port)[1])
	
	def getChainHashOfId(self, id):
		pk, sk = self.getKeys()
		A = {
			'msg': 'I want your chain hash',
			'public key': pk,
			'timestamp': time.time()
		}
		A['sig'] = rsa.sign(json.dumps(A, sort_keys = True), sk)
		A = 'get_chain_hash {}'.format(json.dumps(A))
		response = self._local.command(A, id)
		if response:
			A = json.loads(response)
			if type(A) == dict:		
				sig = A.pop('sig')
				if rsa.verify(sig, json.dumps(A, sort_keys = True), A['public key']):
					return A['chain hash']
		return None
		
	def getKeys(self):
		return self._local.getKeys()
		
	def updateKeys(self, key, bits = RSA_BITS):
		return self._local.updateKeys(key, bits)
		
	def getTurnout(self):
		self._chainMutex.acquire()
		tot_votes_till_now = self._chain.totalTransactionsInChain - 1
		node.mutexReleaser(self._chainMutex)
		return tot_votes_till_now, TOTAL_VOTERS
	
	@node.repeatAndSleep(UPDATE_CHAIN_INT)
	def updateChain(self, ret = True):
		chainChoice =  {}
		self.updateNeighbours(ret = False)
		self._neighboursMutex.acquire()
		for k, v in self.getNeighbours().items():
			if v.ping:
				id = v.id()
				chain_hash = self.getChainHashOfId(id)
				if chain_hash:
					if chain_hash not in chainChoice:
						chainChoice[chain_hash] = [id, 0]
					else:
						chainChoice[chain_hash][1] += 1
		node.mutexReleaser(self._neighboursMutex)
		max_vote = 1
		my_id = self.id()
		max_voted_chain_id = my_id
		for k, v in chainChoice.items():
			if v[1] > max_vote:
				max_vote = v[1]
				max_voted_chain_id = v[0]
		if max_voted_chain_id != my_id:
			chain = self.getChainOfId(max_voted_chain_id)
			if chain:
				self._chainMutex.acquire()
				pendTransactions = self._chain.pendingTransactions
				self._chain = blockchain.Blockchain(chain)
				for k, v in pendTransactions.items():
					self._chain.addTransaction(k, v)
				node.mutexReleaser(self._chainMutex)
		return ret
		
	@node.repeatAndSleep(MINING_INT)
	def mine(self, ret = True):
		if (self._chain.isMineable() and self.isMiner()) or self._chain.gottaMine():
			transactions = self._chain.mineableTransactions
			self._chain.mineableTransactionsMutex.acquire()
			self._chain.mineableTransactions = {}
			node.mutexReleaser(self._chain.mineableTransactionsMutex)
			self._chainMutex.acquire()
			block = {
					'index': len(self._chain.chain) + 1,
					'timestamp': time.time(),
					'proof': None,
					'transactions': transactions,
					'total transactions': len(transactions),
					'prev hash': blockchain.hash(self._chain.lastBlock)
			}
			node.mutexReleaser(self._chainMutex)
			block['proof'] = blockchain.proofOfWork(self._chain.lastBlock['proof'], block['prev hash'])
			self._chainMutex.acquire()
			self._chain.addBlock(block)
			node.mutexReleaser(self._chainMutex)
			self.__broadcastBlock(block)
		return ret
		
	def __broadcastBlock(self, block):
		pk, sk = self.getKeys()
		block['public key'] = pk
		block['sig'] = rsa.sign(json.dumps(block, sort_keys = True), sk)
		block = dict(block)
		block['id'] = self.id()
		self.__broadcastUtil(block, 'broadcast_block')
		
	def	__broadcastUtil(self, A, cmd, id = None):
		self.updateNeighbours(False)
		self._neighboursMutex.acquire()
		for k, v in self.getNeighbours().items():
			v_id = v.id()
			if v_id != id:
				B = '{} {}'.format(cmd, json.dumps(A))
				v.command(B)
		node.mutexReleaser(self._neighboursMutex)
		
	def __validateOfficerSignatures(self, transaction):
		r = transaction['random nonce']
		return rsa.verify(transaction['blo signature'], r, BLO_PUBLIC_KEY) and rsa.verify(transaction['ext-officer signature'], r, EXT_OFFICER_PUBLIC_KEY)
		
	def writeChain(self):
		self._chain.writeChain()
		
	def delChain(self):
		self._chain.delChain()
