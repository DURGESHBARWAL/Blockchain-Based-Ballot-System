import Crypto.Cipher.AES as aes, Crypto.Hash.HMAC as hmac, hashlib

HASHALGO = hashlib.blake2s

def makeIt32(b_string):
	b_string += b'1'
	l = len(b_string)
	for i in range(32 - l):
		b_string += b'0'
	return b_string
	
def symmEncryption(string, key):
	string = string.encode('utf-8')
	string_key = HASHALGO('{}'.format(key).encode('utf-8')).digest()
	enc = aes.new(string_key)
	enc_string = b''
	was_short = b'0'
	for i in range(0, len(string), 32):
		cut_string = string[i : i + 32]
		if len(cut_string) != 32:
			cut_string = makeIt32(cut_string)
			was_short = b'1'
		enc_string += enc.encrypt(cut_string)
	msg = was_short + enc_string
	hmac_ob = hmac.new(string_key)
	hmac_ob.update(msg)
	return msg + hmac_ob.digest()

def symmDecryption(enc_string, key):
	t = len(enc_string) - 16
	enc_string, hmac_digest = enc_string[:t], enc_string[t:]
	string_key = HASHALGO('{}'.format(key).encode('utf-8')).digest()
	hmac_ob = hmac.new(string_key)
	hmac_ob.update(enc_string)
	if hmac_digest != hmac_ob.digest():
		raise Exception
	dec = aes.new(string_key)
	if enc_string[0] == 49:
		was_short = True
	else:
		was_short = False
	enc_string = enc_string[1:]
	dec_string = b''
	for i in range(0, len(enc_string), 32):
		cut_string = enc_string[i : i + 32]
		dec_string += dec.decrypt(cut_string)
	dec_string = dec_string.decode('utf-8')
	if was_short:
		for i in range(len(dec_string) - 1, 0, -1):
			if dec_string[i] == '1':
				return dec_string[:i]
	return dec_string
	
def writeEncryptedFile(file_path, content, key):
	f = open(file_path, 'wb')
	f.write(symmEncryption(content, key))
	f.close()
	
def readEncryptedFile(file_path, key):
	f = open(file_path, 'rb')
	try:
		x = b''
		for i in f.readlines():
			x += i
		s = symmDecryption(x, key)
		f.close()
		return s 
	except:
		f.close()
		raise Exception('Key error')
