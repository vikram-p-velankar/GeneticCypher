import os
import sys
import time
import ga_encrypt
import ga_decrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESCipher:
    def __init__(self):
        self.key_len = 32 

    def get_key(self):
        return get_random_bytes(self.key_len)

    def encrypt(self, text, key):
        data = text.encode('utf-8')
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce, key):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data.decode('utf-8')
        except (ValueError, TypeError):
            return None 

def run_ga_decrypt(c_bin, k_bin):
    if not c_bin or not k_bin: return "", ""
    
    cipher_list = list(c_bin)
    key_len = len(k_bin)
    dec_bits = []
    
    for i, bit in enumerate(cipher_list):
        dec_bits.append(ga_decrypt._xor(bit, k_bin[i % key_len]))
        
    undiffused_chunks = ga_decrypt.remove_diffusion(''.join(dec_bits))
    plain_binary = ''.join(undiffused_chunks)
    plain_text = ga_decrypt.cvt_key(plain_binary)
    return plain_binary, plain_text

def flip_first_bit(binary_str):
    if not binary_str: return binary_str
    bits = list(binary_str)
    bits[0] = '1' if bits[0] == '0' else '0'
    return "".join(bits)

if __name__ == "__main__":
    print("\n=== STARTING TEST PLAN (TC-01 to TC-07) ===")
    
    aes = AESCipher()
    
    ga_key_bin = None
    ga_cipher_bin = None
    
    aes_key = None
    aes_cipher = None
    aes_tag = None
    aes_nonce = None

    print("\n[TC-01] Happy Path")
    msg = "This is a test message"
    
    try:
        c, c_txt, k, k_txt = ga_encrypt.encrypt(msg)
        _, res_ga = run_ga_decrypt(c, k)
        ga_cipher_bin = c
        ga_key_bin = k
        print(f"  GA-XOR : {'PASS' if res_ga == msg else 'FAIL'}")
    except Exception as e:
        print(f"  GA-XOR : ERROR ({e})")

    if aes:
        aes_key = aes.get_key()
        aes_cipher, aes_tag, aes_nonce = aes.encrypt(msg, aes_key)
        res_aes = aes.decrypt(aes_cipher, aes_tag, aes_nonce, aes_key)
        print(f"  AES-GCM: {'PASS' if res_aes == msg else 'FAIL'}")

    print("\n[TC-02] Edge Case: Empty Input")
    try:
        temp_c, _, _, _ = ga_encrypt.encrypt("")
        print(f"  GA-XOR : PASS (Result length: {len(temp_c)})")
    except Exception as e:
        print(f"  GA-XOR : FAIL ({e})")

    print("\n[TC-03] Long Input ('A' * 1000)")
    long_str = "A" * 1000
    start = time.time()
    c_long, _, k_long, _ = ga_encrypt.encrypt(long_str)
    dur = time.time() - start
    _, res_long = run_ga_decrypt(c_long, k_long)
    print(f"  GA-XOR : {'PASS' if res_long == long_str else 'FAIL'} (Time: {dur:.4f}s)")

    print("\n[TC-05] Security: Wrong Key Decryption")
    
    if ga_cipher_bin and ga_key_bin:
        wrong_ga_key = flip_first_bit(ga_key_bin)
        _, bad_res = run_ga_decrypt(ga_cipher_bin, wrong_ga_key)
        print(f"  GA-XOR : {'PASS' if bad_res != msg else 'FAIL'} (Result: '{bad_res[:15]}...')")

    if aes and aes_cipher:
        wrong_aes_key = aes.get_key()
        bad_aes_res = aes.decrypt(aes_cipher, aes_tag, aes_nonce, wrong_aes_key)
        print(f"  AES-GCM: {'PASS' if bad_aes_res is None else 'FAIL'} (Result: {bad_aes_res})")

    print("\n[TC-06] Security: Tampering (Ciphertext bit flip)")
    if ga_cipher_bin:
        tampered_c = flip_first_bit(ga_cipher_bin)
        _, tampered_res = run_ga_decrypt(tampered_c, ga_key_bin)
        print(f"  GA-XOR : {'PASS' if tampered_res != msg else 'FAIL'}")

    if aes and aes_cipher:
        ba = bytearray(aes_cipher)
        ba[0] ^= 1 
        tampered_aes_c = bytes(ba)
        
        tampered_aes_res = aes.decrypt(tampered_aes_c, aes_tag, aes_nonce, aes_key)
        print(f"  AES-GCM: {'PASS' if tampered_aes_res is None else 'FAIL'} (Result: {tampered_aes_res})")

    print("\n[TC-07] Performance: Key Gen (100 Iterations)")
    
    start = time.time()
    for _ in range(100):
        ga_encrypt.create_key()
    print(f"  GA-XOR : {time.time() - start:.4f} seconds")

    if aes:
        start = time.time()
        for _ in range(100):
            aes.get_key()
        print(f"  AES-GCM: {time.time() - start:.4f} seconds")

    print("\nTest Suite Completed.")