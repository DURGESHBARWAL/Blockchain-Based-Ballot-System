import random

def isPrime(n, k = 5):
	if n < 2:
		return False
	elif n == 2 or n == 3:
		return True
	elif n & 1 == 0:
		return False
	d = n - 1
	r = 0
	while d & 1 == 0:
		d >>= 1
		r += 1
	i = 0
	q = n - 1
	while i < k:
		a = random.randrange(2, q)
		x = pow(a, d, n)
		if x == 1 or x == n - 1:
			i += 1
			continue
		j = 1
		flag = True
		while j < r:
			x = pow(x, 2, n)
			if x == 1:
				return False
			if x == n - 1:
				i += 1
				flag = False
				break
			j += 1
		if flag:
			return False
	return True
	
def isEven(x):
	'''returns True if x is even
	'''
	return x & 1 == 0
		
def getNPrimeNumbers(n, bits):
	'''returns N prime numbers
	'''
	if n < 0:
		return
	A = []
	while len(A) != n:
		p = random.getrandbits(bits)
		if isEven(p):
			p += 1
		if isPrime(p):
			A.append(p)
	return A[0] if n == 1 else A
	
def inverse(a, n):
	'''returns b such that a*b = 1 (mod n)
	'''
	if isinstance(a, int) and isinstance(n, int):
		t, new_t = 0, 1
		r, new_r = n, a
		while new_r != 0:
			q = r // new_r
			r, new_r = new_r, r - new_r * q
			t, new_t = new_t, t - new_t * q
		if r == 1:
			if t < 0:
				t += n
			return t

def stringToNumber(s):
	'''encodes a string s to a eq number s_
	'''
	s_ = 0
	for i in s:
		s_ = (s_ << 8) + ord(i)
	return s_
		
def numberToString(s_):
	'''encodes a number s_ to a eq string s
	'''
	s = ''
	prev = 0
	now = 8
	while True:
		t = chr((s_ - ((s_ >> now) << now)) >> prev)
		if t == '\x00':
			break
		s = t + s
		prev = now
		now += 8
	return s
