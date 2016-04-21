#Nonce Based CTR Encryption
- AES CTR mode
- 92-bit randomly chosen nonce
- 32-bit counter incremented for each block
- For each block:  
- Highly parallelizable
- Decryption & Encryption undergo same routine (minimized code)
  - ```ciphertext = AES_Enc(nonce || counter) XOR plaintext```
  - ```plaintext = AES_Enc(nonce || counter) XOR ciphertext```
- Finally encrypt a final tag with a 64 bit message length integer and 64 bit expiration token
  - ```enc_tag = AES_Enc(nonce || counter) XOR (msgLen || expireToken)```

#Keccak Hask Function with Merkle Tree Hashing
- SHA3 (Keccak) Hashing with 256 bit output
- Reduce inputs (tree leaves) to a root by hashing adjacent pairs
- Final root is a 256 bit output
- Highly parallelizable

#Keccak HMAC & Verification
- SHA3 (Keccak) HMAC with 256 bit output
- Absorbed Inputs (in this order):
  - 256-bit root of Merkle Tree
  - 256-bit secret authentication key
  - 128-bit encrypted tag from last encryption routine block
- Output is a 256 bit tag
- Verification requires:
  - Comparing the HMAC tag value
  - Decrypting the final encrypted block (i.e. enc_tag) to compare expire token and message length


  
