import hashlib, time, json, requests, node, threading, os

HASHALGO = hashlib.blake2s
ENCTYPE = 'utf-8'

FORCE_MINING_THRESHOLD = 10

def validateChain(chain):
	if isinstance(chain, Blockchain):
		chain = chain.chain
	elif isinstance(chain, dict):
		chain = chain['chain']
	elif isinstance(chain, list):
		pass
	else:
		raise TypeError('Expected type of chain: either instance of Blockchain or a Blockchain object\'s dict')
	for i in range(1, len(chain)):
		if chain[i]['prev hash'] != hash(chain[i - 1]):
			return False
		if not validateProof(chain[i]['proof'], chain[i - 1]['proof'], hash(chain[i - 1])):
			return False
	return True
	
def hash(block):
	blockString = json.dumps(block, sort_keys = True).encode(ENCTYPE)
	return HASHALGO(blockString).hexdigest()
	
def validateProof(proof, lastProof, prevHash):
	guessString = '{}{}{}'.format(prevHash, lastProof, proof).encode(ENCTYPE)
	guessHash = HASHALGO(guessString).hexdigest()
	return guessHash[:4] == '0000'
	
def proofOfWork(lastProof, prevHash):
	proof = 0
	while not validateProof(proof, lastProof, prevHash):
		proof += 1
	return proof
	
class Blockchain:
	def __init__(self, dictionary = None):
		if dictionary:
			if isinstance(dictionary, dict):
				self.__dict__ = dictionary
			else:
				raise TypeError('dictionary is required as a arg, given: {}'.format(type(dictionary)))
		else:
			self.chain = [
				{
					'index': 1,
					'timestamp': time.time(),
					'proof': 1,
					'transactions': {'msg': 'Genesis'},
					'total transactions': 1,
					'prev hash': '1',
				}
			]
			self.pendingTransactions = {}
			self.mineableTransactions = {}
			self.totalTransactionsInChain = 1
		self.mineableTransactionsMutex = threading.BoundedSemaphore()
		self.pendingTransactionsMutex = threading.BoundedSemaphore()
	
	def __len__(self):
		return len(self.chain)
		
	def isMineable(self):
		if len(self.pendingTransactions) > 0 or len(self.mineableTransactions) > 0:
			self.pendingTransactionsMutex.acquire()
			for k, v in self.pendingTransactions.items():
				if k not in self.mineableTransactions:
					self.mineableTransactionsMutex.acquire()
					self.mineableTransactions[k] = v
					self.mineableTransactionsMutex.release()
			self.pendingTransactions = {}
			self.pendingTransactionsMutex.release()
			return True
		return False
	
	def gottaMine(self):
		self.mineableTransactionsMutex.acquire()
		l = len(self.mineableTransactions) >= FORCE_MINING_THRESHOLD
		self.mineableTransactionsMutex.release()
		return l
		
	def __repr__(self):
		A = '[\n'
		for i in self.chain:
			A += '\t{\n'
			for k, v in sorted(i.items()):
				A += '\t\t{}: {}\n'.format(k, v)
			A += '\t}\n'
		A += ']\n'
		return A
	
	def printChain(self):
		print('[')
		for i in self.chain:
			print('\t{')
			for k, v in sorted(i.items()):
				print('\t\t{}: {}'.format(k, v))
			print('\t}')
		print(']')
		
	@property
	def lastBlock(self):
		if len(self) != 0:
			return self.chain[-1]
			
	def validateTransaction(self, key, transaction):
		self.pendingTransactionsMutex.acquire()
		if key not in self.pendingTransactions:
			self.pendingTransactionsMutex.release()
			self.mineableTransactionsMutex.acquire()
			if key not in self.mineableTransactions:
				self.mineableTransactionsMutex.release()
				for block in self.chain:
					if key in block['transactions']:
						return False
				return True
			self.mineableTransactionsMutex.release()
			return False
		self.pendingTransactionsMutex.release()
		return False
		
	def addTransaction(self, key, transaction):
		if self.validateTransaction(key, transaction):
			self.pendingTransactionsMutex.acquire()
			self.pendingTransactions[key] = transaction
			self.pendingTransactionsMutex.release()
			return True
		return False
	
	def validateBlock(self, block):
		for k, v in block['transactions'].items():
			for blk in self.chain:
				if k in blk['transactions']:
					return False
		return validateProof(block['proof'], self.lastBlock['proof'], hash(self.lastBlock))
			
	def addBlock(self, block):
		if self.validateBlock(block):
			self.chain.append(block)
			self.totalTransactionsInChain += block['total transactions']
			return True
		return False
		
	def writeChain(self):
		f = open('chain.json', 'w')
		f.write(json.dumps(self.chain, sort_keys = True))
		f.close()
		
	def delChain(self):
		os.remove('chain.json')
