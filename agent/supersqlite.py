import sqlite3, hashlib, os, threading

def synchronize(func):
	def inner(self, *args, **kwargs):
		self._mutex.acquire()
		ret = None
		try:
			ret = func(self, *args, **kwargs)
		except:
			pass
		safeCall(self._mutex.release)
		return ret
	return inner
	
def safeCall(f):
	try:
		f()
	except:
		pass

class SSQLiteManager:
	
	def __init__(self, db_name):
		self._conn = sqlite3.connect(db_name)
		self._db_name = db_name
		self._mutex = threading.BoundedSemaphore()
		
	@property
	def db_name(self):
		return self._db_name
	
	@synchronize
	def listTables(self):
		c = self._conn.execute('SELECT name FROM SQLITE_MASTER WHERE TYPE = "table"')
		ret = c.fetchall()
		c.close()
		return ret
		
	def __contains__(self, table_name):
		return table_name in self.listTables()
	
	@synchronize
	def desc(self, table_name):
		c = self._conn.execute('SELECT * FROM {} LIMIT 1'.format(table_name))
		ret = c.description
		c.close()
		return ret

	@synchronize
	def createTableIfNotExists(self, table_name, attrs):
		self._conn.execute('CREATE TABLE IF NOT EXISTS {} ({})'.format(table_name, attrs))
		return True
	
	@synchronize
	def createTable(self, table_name, attrs):
		self._conn.execute('CREATE TABLE {} ({})'.format(table_name, attrs))
		return True
		
	@synchronize
	def len(self, table_name):
		return self._conn.execute('SELECT COUNT(*) FROM {}'.format(table_name)).fetchall()[0][0]
	
	@synchronize
	def insert(self, table_name, values):
		self._conn.execute('INSERT INTO {} VALUES ({})'.format(table_name, values))
		return True
	
	@synchronize
	def select(self, table_name, attrs = '*', cond = '2 == 2', orderby = '', asc = True, limit = None):
		if orderby == '':
			if limit:
				c = self._conn.execute('SELECT {} FROM {} WHERE {} LIMIT {}'.format(attrs, table_name, cond, limit))
			else:
				c = self._conn.execute('SELECT {} FROM {} WHERE {}'.format(attrs, table_name, cond))
		else:
			if limit:
				c = self._conn.execute('SELECT {} FROM {} WHERE {} ORDER BY {} {} LIMIT {}'.format(attrs, table_name, cond, orderby, 'asc' if asc else 'desc', limit))
			else:
				c = self._conn.execute('SELECT {} FROM {} WHERE {} ORDER BY {} {}'.format(attrs, table_name, cond, orderby, 'asc' if asc else 'desc'))
		ret = c.fetchall()
		c.close()
		return ret
	
	@synchronize
	def update(self, table_name, set_commands, cond = '2 == 2'):
		self._conn.execute('UPDATE {} SET {} WHERE {}'.format(table_name, set_commands, cond))
		return True
		
	@synchronize
	def delete(self, table_name, cond = '2 == 2'):
		self._conn.execute('DELETE FROM {} WHERE {}'.format(table_name, cond))
		return True

	@synchronize
	def truncate(self, table_name):
		return self.deleteFrom(table_name)

	@synchronize
	def drop(self, table_name):
		self._conn.execute('DROP TABLE {}'.format(table_name))
		return True

	@synchronize
	def rollback(self):
		self._conn.rollback()
		return True

	@synchronize
	def commit(self):
		self._conn.commit()
		return True

	@synchronize
	def close(self):
		self._conn.close()
		return True
	
	@synchronize
	def hash(self, hashalgo = hashlib.md5):
		f = open(self.db_name, 'rb')
		s = b''
		for i in f.readlines():
			s += i
		f.close()
		return hashalgo(s)
	
def removeDb(ssqlmanager):
	ssqlmanager.close()
	os.remove(ssqlmanager.db_name)
