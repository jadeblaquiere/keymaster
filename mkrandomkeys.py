#!/usr/bin/python
# Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ecpy nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ecpy.point import Point, Generator
import ecpy.curves as curves
from Crypto.Random import random
from Crypto.Hash import RIPEMD
from hashlib import sha256
import hashlib
from binascii import hexlify, unhexlify
from base58 import b58encode, b58decode

# set up elliptic curve environment
c = curves.curve_secp256k1
Point.set_curve(c)
G = Generator(c['G'][0], c['G'][1])

#mainnet
pub_prefix = '00'
prv_prefix = '80'
#testnet
pub_prefix = '6f'
prv_prefix = 'ef'
#simtest
pub_prefix = '3f'
prv_prefix = '64'
#ctindigonet
pub_prefix = '1c'
prv_prefix = 'bb'
#ctrednet
pub_prefix = '50'
prv_prefix = 'a3'

pub_prefix = '1c'
prv_prefix = 'bb'


def priv_key_fmt(prefix, keyhx):
    # generate WIF format
    # see: https://en.bitcoin.it/wiki/Wallet_import_format
    # add header prefix
    h_key = prefix + keyhx
    # calc checksum
    cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
    # encode base58
    return b58encode(unhexlify(h_key + cksum))

def priv_key_fmt_C(prefix, keyhx):
    # generate WIF format
    # see: https://en.bitcoin.it/wiki/Wallet_import_format
    # add header prefix
    h_key = prefix + keyhx + '01'
    # calc checksum
    cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
    # encode base58
    return b58encode(unhexlify(h_key + cksum))

def priv_key_decode(keyb58):
    raw = hexlify(b58decode(keyb58))
    h_key = raw[:66]
    cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
    if cksum != raw[66:].decode('utf-8'):
        raise ValueError('checksum mismatch')
    return h_key[2:].decode('utf-8')

def priv_key_decode_C(keyb58):
    raw = hexlify(b58decode(keyb58))
    h_key = raw[:68]
    cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
    if raw[66:68].decode('utf-8') != '01':
        raise ValueError('format error')
    if cksum != raw[68:].decode('utf-8'):
        raise ValueError('checksum mismatch')
    return h_key[2:66].decode('utf-8')

def pub_key_fmt(prefix, keyhx):
    # generate V1 Address format
    # see: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    # hash key - sha256 then ripemd160
    h = RIPEMD.new(sha256(unhexlify(keyhx)).digest())
    # add header prefix
    h_hashkey = prefix + hexlify(h.digest()).decode('utf-8')
    # calc checksum
    cksum = sha256(sha256(unhexlify(h_hashkey)).digest()).hexdigest()[:8]
    # encode base58
    return b58encode(unhexlify(h_hashkey + cksum))

def pub_key_fmt_C(prefix, keyhx):
    # generate V1 Address format
    # see: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    # hash key - sha256 then ripemd160
    keyval = keyhx
    keybin = int(keyhx,16)
    if keyhx[:2] == '04':
        keyval = ('03' if (keybin % 2) else '02') + keyhx[2:66]
    elif (keyhx[:2] != '02') and (keyhx[:2] != '03'):
        raise ValueError('input is not ECC point format')
    print('keyval = ' + keyval)
    h = RIPEMD.new(sha256(unhexlify(keyval)).digest())
    # add header prefix
    h_hashkey = prefix + hexlify(h.digest()).decode('utf-8')
    # calc checksum
    cksum = sha256(sha256(unhexlify(h_hashkey)).digest()).hexdigest()[:8]
    # encode base58
    return b58encode(unhexlify(h_hashkey + cksum))

if __name__ == '__main__':
    # private key is a random number between 1 and n 
    # (where n is "order" of curve generator point G)
    p = random.randint(1,c['n']-1)
    # p = 0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    # p = 0x1111111111111111111111111111111111111111111111111111111111111111;
    phx = '%064x' % p
    print("PRIVATE KEY MATH : ")
    print('rand privkey = ' + phx)
    
    wif_priv = priv_key_fmt(prv_prefix, phx)
    print("WIF privkey = " + wif_priv)
    if p == 0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D:
        assert wif_priv == '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
    if p == 0x1111111111111111111111111111111111111111111111111111111111111111:
        assert wif_priv == '5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh'
    
    #check that we can recover p from WIF
    rhx = priv_key_decode(wif_priv)
    # print('rxh, phx =', rhx, phx)
    assert rhx == phx
    
    wif_priv_C = priv_key_fmt_C(prv_prefix, phx)
    print("WIF privkey Compressed = " + wif_priv_C)
    if p == 0x1111111111111111111111111111111111111111111111111111111111111111:
        assert wif_priv_C == 'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp'
    
    #check that we can recover p from WIF
    rhx = priv_key_decode_C(wif_priv_C)
    # print('rxh, phx =', rhx, phx)
    assert rhx == phx
    
    print("PUBLIC KEY MATH : ")
    # p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    P = G * p
    Pa = P.affine()
    pbhx = '04' + ('%064x' % Pa[0]) + ('%064x' % Pa[1])
    print("point long fmt = " + pbhx)
    wif_pub = pub_key_fmt(pub_prefix, pbhx)
    print("WIF pubkey = " + wif_pub)
    if p == 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725:
        assert wif_pub == '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
    if p == 0x1111111111111111111111111111111111111111111111111111111111111111:
        assert wif_pub == '1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a'
        
    wif_pub_C = pub_key_fmt_C(pub_prefix, pbhx)
    print("WIF pubkey Compressed = " + wif_pub_C)
    if p == 0x1111111111111111111111111111111111111111111111111111111111111111:
        assert wif_pub_C == '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9'
        
    if False:
        for i in range(0,255):
            ihx = '%02x' % i
            print(ihx + ' :priv: ' + priv_key_fmt(ihx, phx) + ' ' + priv_key_fmt_C(ihx, phx)) 

        for i in range(0,255):
            ihx = '%02x' % i
            print(ihx + ' :pub: ' + pub_key_fmt(ihx, pbhx))
    
    if False:
        
        refprv = 'xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY'
        refder = 'xprv9z82SKRcnNidyodMRmo4T96QD481VWNAxK7LgJghFdgDvsc95AuBFbjUuqhzkynYgx2ay1VN5J6yAUwpCPo4L9pjUoX1HwNx9xBFKR4y8yv'
        refderp = 'xpub6D7NqpxWckGwCHhpXoL4pH38m5xVty62KY2wUh6JoyDCofwHciDRoQ3xm7WAg2ffpHaC6X4bEociYq81niyNUGhCxEs6fDFAd1LPbEmzcAm'
        
        refhx = hexlify(b58decode(refprv)).decode('utf8')
        rdehx = hexlify(b58decode(refder)).decode('utf8')
        rdphx = hexlify(b58decode(refderp)).decode('utf8')
        
        print('rhx ' + refhx)
        print('rdvx ' + rdehx)
        print('rdpx ' + rdphx)
        
        refprv = 'cprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY'
        refder = 'cprv9z82SKRcnNidyodMRmo4T96QD481VWNAxK7LgJghFdgDvsc95AuBFbjUuqhzkynYgx2ay1VN5J6yAUwpCPo4L9pjUoX1HwNx9xBFKR4y8yv'
        refderp = 'cpub6D7NqpxWckGwCHhpXoL4pH38m5xVty62KY2wUh6JoyDCofwHciDRoQ3xm7WAg2ffpHaC6X4bEociYq81niyNUGhCxEs6fDFAd1LPbEmzcAm'
        
        refhx = hexlify(b58decode(refprv)).decode('utf8')
        rdehx = hexlify(b58decode(refder)).decode('utf8')
        rdphx = hexlify(b58decode(refderp)).decode('utf8')
        
        print('crhx ' + refhx)
        print('crdvx ' + rdehx)
        print('crdpx ' + rdphx)
        
        refprv = 'zprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY'
        refder = 'zprv9z82SKRcnNidyodMRmo4T96QD481VWNAxK7LgJghFdgDvsc95AuBFbjUuqhzkynYgx2ay1VN5J6yAUwpCPo4L9pjUoX1HwNx9xBFKR4y8yv'
        refderp = 'zpub6D7NqpxWckGwCHhpXoL4pH38m5xVty62KY2wUh6JoyDCofwHciDRoQ3xm7WAg2ffpHaC6X4bEociYq81niyNUGhCxEs6fDFAd1LPbEmzcAm'
        
        refhx = hexlify(b58decode(refprv)).decode('utf8')
        rdehx = hexlify(b58decode(refder)).decode('utf8')
        rdphx = hexlify(b58decode(refderp)).decode('utf8')
        
        print('zrhx ' + refhx)
        print('zrdvx ' + rdehx)
        print('zrdpx ' + rdphx)
