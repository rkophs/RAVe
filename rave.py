import sha3
import math
import time
import binascii
import threading
import Queue 
import gc
from Crypto.Cipher import AES
		
#Performs the encryption and decryption of a message in AES/CTR/256 with padding
#Encryption additionally encrypts a final block containing an expiration token and message length
class Cipher:

	@staticmethod
	def sxor(s1,s2):
		return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

	@staticmethod 
	def pad(s):
		return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

	@staticmethod
	def unpad(s):
		return s[0:-ord(s[-1])]

	@staticmethod
	def _int32_to_bytes(x):
		result = chr((x >> 24) & 0xFF) + chr((x >> 16) & 0xFF)
		result += chr((x >> 8) & 0xFF) + chr(x & 0xFF)
		return result

	def __init__(self, enc_key, nonce):
		self.cipher = AES.new(enc_key, AES.MODE_ECB)
		self.enc_key = enc_key
		self.secret = nonce

	def encrypt(self, block, counter):
		iv = self.secret + Cipher._int32_to_bytes(counter);
		enc = self.cipher.encrypt(iv)
		return Cipher.sxor(block, enc);

class HashThread(threading.Thread):
	def __init__(self, results):
		threading.Thread.__init__(self)
		self.results = results
	
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
		elif length == 2:
			half = length // 2;
			return self._hash(self._merkle_hash(inputs[:half]), self._merkle_hash(inputs[half:]))
	def run(self):
		while True:
			next = self.results.pop();
			if next == None:
				continue
			elif next == -1:
				break
			elif next[0] == -1:
				break
			layer = next[0]
			key = next[1]
			inputs = next[2]
			self.results.pushChild(layer + 1, key // 2, self._merkle_hash(inputs))

class CipherThread (threading.Thread):

	def __init__(self, enc_key, enc_nonce, queue, results):
		threading.Thread.__init__(self)
		self.enc_key = enc_key
		self.enc_nonce = enc_nonce
		self.queue = queue
		self.results = results
		self.cipher = Cipher(self.enc_key, self.enc_nonce)

	def run(self):
		while True:
			tup = self.queue.get(); #[counter, block ]
			if tup == None:
				break
			counter = tup[0]
			block = tup[1]
			enc = self.cipher.encrypt(block, counter)
			self.results.pushBlock(counter, block, enc)

class BlockLayers:
	def __init__(self, entry_count, saveBlocks, encrypt, threadCount):
		self.queue = Queue.Queue(-1)
		self.layer_count = int(math.ceil(math.log(entry_count,2)) + 1)
		self.partials = {}
		self.expects = []
		self.locks = []

		expect = entry_count
		for i in xrange(0, self.layer_count):
			self.partials[i] = {}
			self.expects.append(expect)
			self.locks.append(threading.Lock())
			expect = (expect + (expect % 2)) // 2

		self.saveBlocks = saveBlocks
		self.blocks = []
		self.encrypt = encrypt
		self.threadCount = threadCount

	def pushChild(self, layer, key, value):
		if self.layer_count - 1 == layer:
			self.root = value
			for i in xrange(0, self.threadCount):
				self.queue.put(-1)
			return

		i = key - (key % 2)
		if key == self.expects[layer] - 1:
			self.queue.put([layer, i, [value]])
			return

		self.locks[layer].acquire()
 		if i in self.partials[layer]:
			res = self.partials[layer][i]
			res[key % 2] = value
			self.queue.put([layer, i, res])
			del self.partials[layer][i]
		else:
			res = [None, None]
			res[key % 2] = value
			self.partials[layer][i] = res
		self.locks[layer].release()

	def pushBlock(self, key, before_value, after_value):
		if key == self.expects[0]:
			self.cipher_tag = after_value if self.encrypt else before_value
			self.plain_tag = before_value if self.encrypt else after_value
			return

		value = after_value if self.encrypt else before_value
		self.pushChild(0, key, value)

		if self.saveBlocks:
			size = len(after_value)
			loc = key*size
			self.blocks[loc:loc+size] = after_value

	def get_blocks(self):
		return self.blocks

	def get_root(self):
		return self.root

	def get_cipher_tag(self):
		return self.cipher_tag

	def get_plain_tag(self):
		return self.plain_tag

	def pop(self):
		return self.queue.get()

class Producer(threading.Thread):

	def __init__(self, blocks, tag, queue, qsize):
		threading.Thread.__init__(self)
		self.blocks = blocks
		self.qsize = qsize
		self.queue = queue
		self.tag = tag

	def run(self):
		blockCount = len(self.blocks)
		self.queue.put([blockCount, self.tag])
		for i in range(len(self.blocks)):
			block = self.blocks[i]
			self.queue.put([i, block])
		for i in range(self.qsize):
			self.queue.put(None)

class RAVe:
	@staticmethod
	def _split_every(n, s):
		return [ s[i:i+n] for i in xrange(0, len(s), n) ]

	@staticmethod
	def _int64_to_bytes(x):
		result = chr((x >> 56) & 0xFF) + chr((x >> 48) & 0xFF)
		result += chr((x >> 40) & 0xFF) + chr((x >> 32) & 0xFF)
		result += chr((x >> 24) & 0xFF) + chr((x >> 16) & 0xFF)
		result += chr((x >> 8) & 0xFF) + chr(x & 0xFF)
		return result

	def __init__(self, auth_key, enc_key, enc_nonce, threadCount):
		self.auth_key = auth_key
		self.enc_key = enc_key
		self.enc_nonce = enc_nonce
		self.threadCount = threadCount
		self.queue = Queue.Queue(threadCount)

	def _routine(self, blocks, tag, encrypt):
		threads = []
		producer = Producer(blocks, tag, self.queue, self.threadCount)
		producer.start()
		threads.append(producer)

		hashState = BlockLayers(len(blocks), True, encrypt, self.threadCount)

		for i in range(self.threadCount):
			cipherT = CipherThread(self.enc_key, self.enc_nonce, self.queue, hashState)
			cipherT.start()
			threads.append(cipherT)
			hashT = HashThread(hashState)
			hashT.start()
			threads.append(hashT)

		while(len(threads) > 0):
			next = threads.pop()
			next.join()

		return hashState

	def _mac(self, tag, root):
		s = sha3.SHA3256()
		s.update(''.join([root, self.auth_key, tag]))
		return s.hexdigest()

	def get_root(self):
		return self.root

	def get_result(self):
		return ''.join(self.blocks)

	def get_tag(self):
		return self.tag

	def get_mac(self):
		return self.mac

	def get_msg_len(self):
		return self.msgLen

	def get_expiration(self):
		return self.expiration

	def authentic(self):
		return self.valid

	def encrypt_and_mac(self, msg, msgLen, expiration):
		self.expiration = int(expiration)
		self.msgLen = msgLen
		tag = RAVe._int64_to_bytes(self.msgLen) + RAVe._int64_to_bytes(self.expiration)
		blocks = RAVe._split_every(16, msg)
		hashState = self._routine(blocks, tag, True)

		self.root = hashState.get_root()
		self.blocks = hashState.get_blocks()
		self.tag = hashState.get_cipher_tag()
		self.mac = self._mac(self.tag, self.root)

	def decrypt_and_verify(self, ciphertext, enc_tag, mac):
		self.mac = mac
		self.tag = enc_tag
		
		cipherblocks = RAVe._split_every(16, ciphertext)
		hashState = self._routine(cipherblocks, enc_tag, False)

		plain_tag = hashState.get_plain_tag()
		self.expiration = int(str(plain_tag[8:16]).encode('hex'), 16)
		self.msgLen = int(str(plain_tag[0:8]).encode('hex'), 16)

		self.root = hashState.get_root()
		self.blocks = hashState.get_blocks()

		self.valid = self.expiration > time.time()
		self.valid = self.valid and self.msgLen == len(ciphertext)
		self.valid = self.valid and self.mac == self._mac(enc_tag, self.root)

def benchmark(auth_key, enc_key, enc_nonce, msg, threadCount, trials):
	msgLen = len(msg)
	expiration = time.time() + 1000000

	send = RAVe(auth_key, enc_key, enc_nonce, threadCount)
	recv = RAVe(auth_key, enc_key, enc_nonce, threadCount)
	start = time.time()
	i = 0
	while(i < trials):
		send.encrypt_and_mac(msg, msgLen, expiration)
		i = i + 1

	end = time.time()
	print "TC: " + str(threadCount) + " msgLen: " + str(msgLen) + " EncTimeAvg: " + str((end - start)/trials)

	start2 = time.time()
	i = 0
	while(i < trials):
		recv.decrypt_and_verify(send.get_result(), send.get_tag(), send.get_mac())
		if(not recv.authentic):
			print "NOT VALID... exiting"
			return
		i = i + 1
	end2 = time.time()
	print "TC: " + str(threadCount) + " msgLen: " + str(msgLen) + " DecTimeAvg: " + str((end2 - start2)/trials)
	print " == Total: " + str((end2 - start2)/trials + (end - start)/trials)
	del send
	del recv

def benchmark_runner():
	auth_key = "0123456789abcdef"
	enc_key = "0123456789012345"
	enc_nonce = "0123456789AB" #This should be random

	#64KB, 256KB, 1MB, 4MB, 16MB, 64MB, 256MB
	msg = "0123456789abcdef"
	msg = msg + msg + msg + msg + msg + msg + msg + msg
	msg = msg + msg + msg + msg + msg + msg + msg + msg
	msg = msg + msg + msg + msg + msg + msg + msg + msg
	msg = msg + msg + msg + msg + msg + msg + msg + msg

	for i in xrange(1,7):
		for tc in [128, 64, 32, 16, 8, 4]:
			gc.collect()
			benchmark(auth_key, enc_key, enc_nonce, msg, tc, 1)
		msg = msg + msg + msg + msg

benchmark_runner()
#main()
