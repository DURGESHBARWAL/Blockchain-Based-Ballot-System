import aesHmac, address, getpass, json

ip, port = input('Enter ur ip/port: ').split('/')
port = int(port)

bits = int(input('How many bits long? '))

file_path = '{}\\{}.rsa.keys'.format(address.getId(ip, port)[0], bits)

passphrase = getpass.getpass('Enter ur password: ')

key_set = json.loads(aesHmac.readEncryptedFile(file_path, passphrase))

c = 1
for keys in key_set:
	print('\nkey: {}'.format(c))
	print('\n\tpublic-key: {}\n\n\tprivate-key: {}'.format(keys[0], keys[1]))
