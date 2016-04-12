import hashlib
import sha3
import math
import time

# Abigail Hertz
# Vidit Jain
# Ryan Kophs
# Project 2 Code
import binascii
from Crypto.Cipher import AES

# Abigail Hertz
# Vidit Jain
# Ryan Kophs
# Project 2 Code

def AES_Function(value, key):
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_ECB)    # Create AES cipher suite using the key
    ciphertext = cipher.encrypt(binascii.unhexlify(value))     # Encrypt the plaintext block given
    return binascii.hexlify(ciphertext)                        # Return the hex of the ciphertext

def encryptCTR(message, nonce, key):
    binNonce =  binascii.hexlify(nonce)            # Convert the nonce to hex
    binKey = binascii.hexlify(key)           # Convert the key to hex
    for i in range(0,16):             
        binNonce = binNonce + '0'        # Add the rest trailing 0s for first counter
        
    numBlocks = len(message)/32
    
    binAD = message[32*(numBlocks-1):]
        
    cipherArray = []
    count = 0
    for i in range(0, len(message) - 32, 32):     # Go through each block and decrypt
        val = message[i:(i+len(binNonce))]              # Isolate a 16 byte block
        ciphertext = AES_Function(binNonce, binKey)       # Run the current block through AES using the key
        intCipher = int(ciphertext,16)                  # Convert to int to be XORed
        intVal = int(val,16)                            # Convert to int to be XORed
        xorVal = intVal ^ intCipher                     # XOR the two values
        xorVal = '{:x}'.format(xorVal)                  # Convert back to hex from int
        cipherArray.append(xorVal)                  # Add the block to the array of ciphertexts
        count = count + 1
        binNonce = binNonce[0:31] + str(count)
        
    ciphertext = AES_Function(binNonce, binKey)
    intCipher = int(ciphertext, 16)
    intVal = int(binAD, 16)
    xorVal = intVal ^ intCipher
    xorVal = '{:x}'.format(xorVal)
    cipherArray.append(xorVal)
        
    print(binascii.unhexlify(''.join(cipherArray[:-1])))                        # Concatenate all ciphertexts together to get final ciphertext

    lastBlock = cipherArray[-1]
    print(binascii.unhexlify(lastBlock[:16]))
    print(int(lastBlock[16:], 16))

def main2():
    message = '9b53cdb14f7026ad2e8411c2a03fce48961058bd9e0e280996efd9d060923eb32b42e9b58e9c63a137037d66245ae19a73e6a6c3cae9b44cd310f35b4db8470b' #'9b53cdb14f7026ad2e8411c2a03fce48961058bd9e0e280996efd9d060923eb32b42e9b58e9c63a137037d66245ae19a73e6a6c3f9d18774d310f35b4db84c9c'    # The message to be encrypted
    nonce = "hi nonce"               # The nonce
    key = "sixteen byte keysixteen byte key"              # The thirty two byte key
    encryptCTR(message, nonce, key)          # Run CTR mode
main2()

def encryptCTR(message, nonce, key):
    binMessage = binascii.hexlify(message)
    binNonce =  binascii.hexlify(nonce)            # Convert the nonce to hex
    binKey = binascii.hexlify(key)           # Convert the key to hex
    binLen = binascii.hexlify(str(len(message)))
    expirationToken = int(time.time())
    binTime = '{:x}'.format(expirationToken)
    for i in range(0,16):             
        binNonce = binNonce + '0'        # Add the rest trailing 0s for first counter
        
    for i in range(0, len(binLen) % 16):
        binLen = binLen + '0'
        
    for i in range(0, len(binTime) % 16):
        binTime = '0' + binTime
        
    binAD = binLen + binTime
        
    cipherArray = []
    count = 0
    for i in range(0, len(binMessage), 32):     # Go through each block and encrypt
        val = binMessage[i:(i+len(binNonce))]              # Isolate a 16 byte block
        ciphertext = AES_Function(binNonce, binKey)       # Run the current block through AES using the key
        intCipher = int(ciphertext,16)                  # Convert to int to be XORed
        intVal = int(val,16)                            # Convert to int to be XORed
        xorVal = intVal ^ intCipher                     # XOR the two values
        xorVal = '{:x}'.format(xorVal)                  # Convert back to hex from int
        cipherArray.append(xorVal)                  # Add the block to the array of ciphertexts
        count = count + 1
        binNonce = binNonce[0:31] + str(count)
        
    ciphertext = AES_Function(binNonce, binKey)
    intCipher = int(ciphertext, 16)
    intVal = int(binAD,16)
    xorVal = intVal ^ intCipher
    xorVal = '{:x}'.format(xorVal)
    cipherArray.append(xorVal)
    print(cipherArray)                         # Concatenate all ciphertexts together to get final ciphertext

def main():
    message = "Multiple messageMultiple messageMultip"    # The message to be encrypted
    nonce = "hi nonce"               # The initialization vector
    key = "sixteen byte keysixteen byte key"              # The thirty two byte key
    encryptCTR(message, nonce, key)          # Run CBC mode

def hmac(nonce, key, msg):
	s = sha3.SHA3256()
	s.update(''.join([nonce, key, msg]))
	return s.hexdigest()

def verify_tag(nonce, key, msg, tag):
	return hmac(nonce, key, msg) == tag

def verify(auth_key, enc_key, enc_nonce, ciphertext, root, tag):
	if verify_tag(root, auth_key, ciphertext[-1], tag):
		#results is array of: [plaintext msg, msgLen, expirationToken]
		results = ["hello world", 11, 1480459664] #decrypt(key, nonce, ciphertext)
		msg = results[0]
		msgLen = results[1]
		if(len(msg) != msgLen):
			return False
		expirationToken = results[2]
		if (expirationToken < time.time()):
			return False
		return True
	else: 
		return False

def hash(a, b):
	s = sha3.SHA3256()
	s.update(''.join([a,b]))
	return s.hexdigest()

def merkle_hash(inputs):
	length = len(inputs)
	if length == 0:
		return inputs
	elif length == 1:
		return inputs[0]
	else:
		half = length // 2;
		return hash(merkle_hash(inputs[:half]), merkle_hash(inputs[half:]))


auth_key = 'auth key'
enc_key = 'enc key'
enc_nonce = 'enc nonce'
msg = 'hello world'

ciphertext = ['cipher block 1', 'cipher block 2', 'cipher block 3', 'cipher block 4']; #encrypt(enc_key, nonce, msg)
root = merkle_hash(ciphertext)
tag = hmac(root, auth_key, ciphertext[-1])

#Transmit over wire at this point

#verified = verify(auth_key, enc_key, enc_nonce, ciphertext, root, tag)
#print verified
main()

