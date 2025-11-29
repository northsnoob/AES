'''
Author: northsnoob@gmail.com
Date: 2025-11-29 21:06:18
LastEditTime: 2025-11-29 21:19:14
Descriptiion: 
VersionList: [1.0] 
'''

from aes_vari import *

if __name__ == '__main__':
    print("start AES test")
    tmp = aes_128_ctr(
        "112233445566778899AABBCCDDEEFF00",
        "AE1200027F72B8480009FDCAE1200027",
        "000102030405060708090A0B0C0D0E0F"
    ) # ans: 0x3afb97eefcbcc16b6c571aa4ff7ac3ad (G-PON)
    answer_chk("3afb97eefcbcc16b6c571aa4ff7ac3ad",tmp.tobytes().hex())
    tmp = aes_128_cmac(
        "112233445566778899AABBCCDDEEFF00",
        "564e4452001122334f4c54234455667753657373696f6e4b"
    ) # ans: 0x795fcf6cb215224087430600dd170f07 (XG-PON)
    answer_chk("795fcf6cb215224087430600dd170f07",tmp.tobytes().hex())
    # SK = AES-CMAC (MSK, (SN | PON-TAG| 0x53657373696f6e4b), 128)
    tmp = aes_128_ecb(
        "6f9c99b8361768937e453b165f609710",
        "112233445566778899AABBCCDDEEFF00"
    ) # ans: 0x4018340d538bb3f50df3186cf075f7b6
    answer_chk("4018340d538bb3f50df3186cf075f7b6",tmp.tobytes().hex())
    
    tmp = aes_128_cmac(
        "6f9c99b8361768937e453b165f609710",
        "112233445566778899AABBCCDDEEFF00" + "33313431353932363533353839373933"
    ) # ans: 0x3cc507bb1731c569ed7b79f8bdc376be (XG-PON)
    answer_chk("3cc507bb1731c569ed7b79f8bdc376be",tmp.tobytes().hex())
    
    tmp = aes_128_cmac(
        "184b8ad4d1ac4af4dd4b339ecc0d3370",
        "01" + "8000" + "490a" + "01000000" +
        "0080000000000000"+"0000000000000000"+"0000000000000000"+"0000000000000000" +
        "00000028"
    ) # ans: 0x78dca53d (XG-PON)
    # Transaction correlation identifier: 0x80 0x00
    # Message type: 0x49 (GET)
    # Device identifier: 0x0A (Baseline OMCI)
    # Managed entity identifier: 0x01 0x00 0x00 0x00 (ONU-G)
    # Message contents: 0x00 0x80 0x00 0x00 .. 0x00
    # OMCI trailer[1:4]: 0x00 0x00 0x00 0x28
    tmp = aes_cut(tmp.tobytes().hex(),32)
    answer_chk("78dca53d",tmp)

    