import random, util, json, Crypto.PublicKey.RSA as rsa, hashlib

SIG_HASHALGO = hashlib.blake2s
SIG_ENCTYPE = 'utf-8'
	
def newKeys(bits = 2048):
	'''returns a tuple (pk, sk), where
	pk: public-key
	sk: secret-key
	'''
	ob = rsa.generate(bits)
	return (ob.e, ob.n, bits), (ob.d, ob.n, bits)
	
def encrypt(mes, k):
	'''encrypts a message, msg using key, k
	'''
	if not isinstance(mes, str):
		mes = str(mes)
	c = ()
	e, n, bits = k
	chunk_size = bits >> 4
	mes_len = len(mes)
	i = 0
	while i < mes_len:
		m = util.stringToNumber(mes[i:i + chunk_size])
		c += (pow(m, e, n), )
		i += chunk_size
	return c
		
def decrypt(c, k):
	'''decrypts a crypted message, msg using key, k
	'''
	mes = ''
	d, n, bits = k
	for i in c:
		m = pow(i, d, n)
		mes += util.numberToString(m)
	return mes
	
def sign(mes, k):
	if not isinstance(mes, str):
		mes = str(mes)
	return encrypt(SIG_HASHALGO(mes.encode(SIG_ENCTYPE)).hexdigest(), k)
	
def verify(signature, mes, k):
	if not isinstance(mes, str):
		mes = str(mes)
	return decrypt(signature, k) == SIG_HASHALGO(mes.encode(SIG_ENCTYPE)).hexdigest()
