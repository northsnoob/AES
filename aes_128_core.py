from GFtable import *
import numpy as np

def xor_bytes(a,b):
    return bytes([x ^ y for x, y in zip(a, b)])

def addRoundKey_r0(_key,_plain):
    return _key ^ _plain

def addRoundKey(_key,_state,rou):
    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    new_key = []
    rot_word = np.roll(_key[:, 3], -1)
    sbox_word = SubBytes(rot_word)
    rcon_word = sbox_word ^ np.array([Rcon[rou],0,0,0],dtype=np.uint8)
    tmp = rcon_word
    for i in range(4):
        tmp = tmp ^ _key[:, i]
        new_key.append(tmp)
    np_key = np.array(new_key, dtype=np.uint8)
    np_key = np_key.transpose()
    return np_key, np_key ^ _state

def SubBytes(_key):
    np_sbox = np.array(Sbox,dtype=np.uint8)
    return np_sbox[_key]

def ShiftRows(block_f):
    for r in range(4):
        block_f[r] = np.roll(block_f[r], -r)
    return block_f

def gf_x2(a):
    tmp = a & 0x80
    en = 0
    if tmp==0x80:
        en = 1
    b = a << 1
    if en == 1:
        b = b ^ 0x1b
    b &= 0xff
    return b

def gf_x3(a):
    b = gf_x2(a)
    b = b ^ a
    return b

def subf_mixc(npar):
    a = npar
    matr = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
        ]
    mixc_list = []
    for i in range(4):
        gf_list = []
        b = 0
        for j in range(4):
            tmp = a[j]
            if matr[i][j] == 2:
                tmp = gf_x2(tmp)
            elif matr[i][j] == 3:
                tmp = gf_x3(tmp)
            gf_list.append(tmp)
        for gf_i in gf_list:
            b ^= gf_i
        mixc_list.append(b)
    return np.array(mixc_list, dtype=np.uint8)

def Mixcolumns(npar):
    mc_list = []
    for j in range(4):
        mc_list.append(subf_mixc(npar[:, j]))
    mc_trans = np.array(mc_list, dtype=np.uint8)
    mc_trans = mc_trans.transpose()
    return mc_trans

def show_mat2arr(mat):
    print(mat.reshape(16, order='F').tobytes().hex())

def AES_rounds(key,pt):
    roundkey0_10 = []
    roundkey0_10.append(key)
    state = addRoundKey_r0(key,pt)
    for i in range(9):
        sbox_trans = SubBytes(state) # OK
        shiftrow_trans = ShiftRows(sbox_trans) # OK
        mc_trans = Mixcolumns(shiftrow_trans) # OK
        key, state = addRoundKey(key,mc_trans,i)
        roundkey0_10.append(key.reshape(16, order='F').tobytes().hex())
    sbox_trans = SubBytes(state)
    shiftrow_trans = ShiftRows(sbox_trans)
    key, state = addRoundKey(key,shiftrow_trans,9)
    return state, roundkey0_10

def aes128_encrypt(key_hex, plaintext_hex):
    key_block = np.frombuffer(bytes.fromhex(key_hex),dtype=np.uint8)
    pt_block = np.frombuffer(bytes.fromhex(plaintext_hex),dtype=np.uint8)
    key_block = key_block.reshape(4, 4, order='F')  # order='F' force column first
    pt_block = pt_block.reshape(4, 4, order='F') 
    aes_out, roundkey0_10_list = AES_rounds(key_block,pt_block)
    aes_out = aes_out.reshape(16, order='F')
    return aes_out, roundkey0_10_list