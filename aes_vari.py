'''
Author: northsnoob@gmail.com
Date: 2025-11-29 21:06:27
LastEditTime: 2025-11-29 21:16:45
Descriptiion: 
'''


# Online Python - IDE, Editor, Compiler, Interpreter
import numpy as np
import aes_128_core as AES_128

def answer_chk(ans,chk):
    print(ans==chk,ans)
    return (ans==chk)

def aes_cut(aeskey,num=64):
    return aeskey[0:int(num/4)]

def aes_128_ecb(key,plaintext):
    aes_key, rndkey0_10_list = AES_128.aes128_encrypt(
        key,
        plaintext
    )
    print("AES-128-ECB:",aes_key.tobytes().hex())
    return aes_key

def aes_128_ctr(key,ctr,plaintext):
    aes_key, rndkey0_10_list = AES_128.aes128_encrypt(
        key,
        ctr
    )
    pt_block = np.frombuffer(bytes.fromhex(plaintext),dtype=np.uint8)
    aes_key = aes_key ^ pt_block
    print("AES-128-CTR:",aes_key.tobytes().hex())
    return aes_key

def aes_128_cmac(key,plaintext):
    pt_len = len(plaintext)
    chunks = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
    if pt_len%32 != 0:
        chunks[-1] = (chunks[-1]+"80").ljust(32, '0')
    L = AES_128.aes128_encrypt(
        key,
        "00000000000000000000000000000000"
    )
 
    L_int = int.from_bytes(L.tobytes(), byteorder='big')
    K1 = L_int << 1
    if (L_int>>127)&1 == 1:
        K1 = K1 ^ 0x87
    K2 = K1 << 1
    if (K1>>127)&1 == 1:
        K2 = K2 ^ 0x87
    K1 &= ((1 << 128) - 1)
    K2 &= ((1 << 128) - 1)
    K1_bytes = K1.to_bytes(16, byteorder='big')
    K2_bytes = K2.to_bytes(16, byteorder='big')
    K1 = np.frombuffer(K1_bytes, dtype=np.uint8)
    K2 = np.frombuffer(K2_bytes, dtype=np.uint8)
    chunks_last = np.frombuffer(bytes.fromhex(chunks[-1]),dtype=np.uint8)
    if pt_len%32 == 0:
        chunks_last = chunks_last ^ K1
    else:
        chunks_last = chunks_last ^ K2
    chunks[-1] = chunks_last.tobytes().hex()
    aes_key = np.zeros(16, dtype=np.uint8)
    for i in range(len(chunks)):
        aes_key ^= np.frombuffer(bytes.fromhex(chunks[i]),dtype=np.uint8)
    
        aes_key, rndkey0_10_list = AES_128.aes128_encrypt(
            key,
            aes_key.tobytes().hex()
        )
    print("AES-128-CMAC:",aes_key.tobytes().hex()) 
    return aes_key
    
    