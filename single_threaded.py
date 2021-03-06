import hashlib
import sha3
import math
import time
import binascii
import struct
import textwrap
from Crypto.Cipher import AES

#Performs the encryption and decryption of a message in AES/CTR/256 with padding
#Encryption additionally encrypts a final block containing an expiration token and message length
class Cipher:

	@staticmethod 
	def pad(s):
		return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

	@staticmethod
	def unpad(s):
		return s[0:-ord(s[-1])]

	@staticmethod
	def _int64_to_bytes(x):
		result = chr((x >> 56) & 0xFF) + chr((x >> 48) & 0xFF)
		result += chr((x >> 40) & 0xFF) + chr((x >> 32) & 0xFF)
		result += chr((x >> 24) & 0xFF) + chr((x >> 16) & 0xFF)
		result += chr((x >> 8) & 0xFF) + chr(x & 0xFF)
		return result

	def __init__(self, enc_key, nonce):
		self.enc_key = enc_key
		self.cnter_cb_called = 0 
		self.secret = nonce

	#Called by AES routine for each block. Returns [ctr_rand_nonce + counter++]
	def _counter_callback(self):
		self.cnter_cb_called += 1
		return self.secret + Cipher._int64_to_bytes(self.cnter_cb_called)

	#Return the encrypted tokens block (must call encrypt() first)
	def tag(self ):
		return self.enc_tag

	#Encrypt a message and appropriate tokens into final block. 
	# Does not add final block to the cipher text. Stores it locall rather.
	def encrypt(self, raw, expireTime):
		cipher = AES.new( self.enc_key, AES.MODE_CTR, counter = self._counter_callback )
		raw_padded = Cipher.pad(raw)
		enc_padded = cipher.encrypt(raw_padded)

		expiration = self._int64_to_bytes(expireTime)
		msgLen = self._int64_to_bytes(len(enc_padded))
		self.enc_tag = cipher.encrypt(msgLen + expiration)

		return enc_padded

	#Return the expiration within an encrypted tag. Must call decryptTokens() first
	def expiration(self):
		return self.expireToken

	#Return the msgLen within an encrypted tag. Must call decryptTokens() first
	def msgLen(self):
		return self.msgLenToken

	#Decrypt a ciphertext.
	def decrypt(self, enc):
		self.cnter_cb_called = 0
		cipher = AES.new(self.enc_key, AES.MODE_CTR, counter = self._counter_callback)
		raw_padded = cipher.decrypt(enc)
		return Cipher.unpad(raw_padded)

	#Decrypt encrypted tokens
	def decryptTokens(self, offset, tag):
		self.cnter_cb_called = offset
		cipher = AES.new(self.enc_key, AES.MODE_CTR, counter = self._counter_callback)
		dec_tag = cipher.decrypt(tag)
		self.expireToken = int(str(dec_tag[8:16]).encode('hex'), 16)
		self.msgLenToken = int(str(dec_tag[0:8]).encode('hex'), 16)

#Produce a mac from a cipher text and encrypted tokens
class Signer:

	def __init__(self, auth_key):
		self.auth_key = auth_key

	#Keccak 256bit hash
	def _hash(self, a, b):
		s = sha3.SHA3256()
		s.update(''.join([a,b]))
		return s.hexdigest()

	def _merkle_hash(self, inputs):
		length = len(inputs)
		if length == 0:
			return inputs
		elif length == 1:
			return inputs[0]
		else:
			half = length // 2;
			return self._hash(self._merkle_hash(inputs[:half]), self._merkle_hash(inputs[half:]))

    #Build root of merkle tree from blocks of ciphertext. 
    # HMAC the root, auth_key and encrypted tokens to produce a mac
	def mac(self, ciphertext, enc_tag):
		root = self._merkle_hash(textwrap.wrap(ciphertext, 16))
		
		s = sha3.SHA3256()
		s.update(''.join([root, self.auth_key, enc_tag]))
		return s.hexdigest()

#Verifiy a cipher text & encrypted tag against a provided MAC
# Must not only match the mac, but check that the message is not expired and that the length
# is correct
class Verifier:
	def __init__(self, auth_key, enc_key, enc_nonce):
		self.signer = Signer(auth_key)
		self.cipher = Cipher(enc_key, enc_nonce)

	def _validMac(self, ciphertext, enc_tag, mac):
		return self.signer.mac(ciphertext, enc_tag) == mac

	def _timely(self):
		return self.cipher.expiration() > time.time()

	def _validMsgLength(self, ciphertext):
		return self.cipher.msgLen() == len(ciphertext)

	def verify(self, ciphertext, enc_tag, mac):
		self.cipher.decryptTokens((len(ciphertext) // 16), enc_tag)
		return self._validMac(ciphertext, enc_tag, mac) and self._timely() and self._validMsgLength(ciphertext)

def main():
	msg = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF"
	msg = msg + msg + msg + msg + msg + msg + msg + msg
	msg = msg + msg + msg + msg

	msg = msg + msg + msg + msg
	msg = msg + msg + msg + msg
	msg = msg + msg + msg + msg
	msg = msg + msg + msg + msg
	msg = msg + msg + msg + msg
	
	print len(msg)
	expiration = int(time.time() + 1000)
	auth_key = "0123456789abcdef"
	enc_key = "0123456789012345"
	enc_nonce = "01234567"

	start = time.time()
	enc_cipher = Cipher(enc_key, enc_nonce)
	dec_cipher = Cipher(enc_key, enc_nonce)

	ciphertext = enc_cipher.encrypt(msg, expiration)
	enc_tag = enc_cipher.tag()

	signer = Signer(auth_key)
	mac = signer.mac(ciphertext, enc_tag)

	verifier = Verifier(auth_key, enc_key, enc_nonce)
	verified = verifier.verify(ciphertext, enc_tag, mac)
	dec_cipher.decrypt(ciphertext)

	end = time.time()

	print str(end - start)
main()