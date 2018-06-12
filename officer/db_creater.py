import supersqlite as ssql, json

db_manager = ssql.SSQLiteManager('public_details.db')

db_manager.drop('OFFICER_DETAILS')
db_manager.drop('ELIGIBLE_VOTERS')

db_manager.createTable('OFFICER_DETAILS', '"public key" TEXT, "address" TEXT, "port" INT')
db_manager.createTable('ELIGIBLE_VOTERS', '"voter id" TEXT PRIMARY KEY, status INT')

def input_officer_details(officer_name):
	print('Enter {} details:'.format(officer_name))
	e = int(input('public exponent: '))
	n = int(input('public modulus: '))
	b = int(input('bits: '))
	addr, port = input('ip/port: ').split('/')
	port = int(port)
	db_manager.insert('OFFICER_DETAILS', '"{}", "{}", {}'.format(json.dumps((e, n, b), sort_keys = True), addr, port))

f = lambda x: input_officer_details(x)

f('BLO')
print()
f('EXT OFFICER')
print()

nv = int(input('Enter number of eligible voters: '))

if nv > 0:
	for i in range(nv):
		db_manager.insert('ELIGIBLE_VOTERS', '"{}", 1'.format(input('{}> '.format(i + 1))))

db_manager.commit()
db_manager.close()
