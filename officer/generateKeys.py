import rsa, aesHmac, address, getpass, json

ip, port = input('Enter ur ip/port: ').split('/')
port = int(port)

bits = int(input('How many bits long? '))

file_path = '{}\\{}.rsa.keys'.format(address.getId(ip, port)[0], bits)

passphrase = getpass.getpass('Enter ur password: ')

key = json.dumps([rsa.newKeys(bits)])

aesHmac.writeEncryptedFile(file_path, key, passphrase)
