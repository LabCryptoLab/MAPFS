# The 256-bit hash function
from Crypto.Hash import SHA256
import hashlib

# The HMAC function
from Crypto.Hash import HMAC
import hmac

# The Advanced Encryption System  CBC Mode(Symmetric Encryption)
from Crypto.Cipher import AES
from Crypto import Random

#The random number generation
import os

# The public key encrypton (RSA)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# The bilinear pairing
from bplib import bp

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point

import time

import json

from mod import Mod

data=[]
message = b'rfvsjbnbkf nikvfabnbrnkbnbknv NBRNTENBBFKEDANKENG KNKFDANKGRNKBGKNBFKTFNBFR  KFBDNKBNFRK BFD BLKBNRFNRF KFNBKEG DNBNRKORMVFS BKRNKRNGRNNB;KNBRNRF KBFRNRJFEM  KFRNBFNKNG NVFRL;SBFBJGERINHKTNBNBITNERKNAKNKVFNKNRAFNKNGRKF;FEKPKEGR  GRGKFM FV;LRMGR;MV,MV;LGRMLGRNV ,;FKDGRMV;MSK NGFAKBRKB FKVNBDKFGTNFVM CXFKNRKADN CNKGRNFD ,VCSNFRKK DDSKTENFKZVFDNVD.NGTLKNMGFD  VFGRAMDCMRJNDNMVSC  MDCSJNF DCDCNSL.N.M NDDDDDDDNCDCJMD,C  ,M ,M ,M ,M ,M ,M ,M ,M ,MDSCJN MDSV CM J DCCMDANFKJN VDNDCKLNVDS DV SJCBJBDSJCBBDJJGRBJBGRJKBKJBGERWBJKJVDBRJVFBLCBVECBFRWVC U V  DCBSKDJEWNFRWBJFRBVFDFENCXBKSANDMXNLKJNEDSAFHFUEDWHGUGFBVBVBVBVBVBVLKENFDLKLKLKLK.NDSA MNSLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKDC S,M,M,M,M,M,M,MJEWEWEWEWEWEWEWEWEWEWEW,Msaddddrehjjhq.JE.JE.JE.JE.JE.JE.JE.JE.JE.JEaf,nnnnnnn cxzzzzzzbewjkewrioooipoiiiiiiiiipcdklbdjcbsnccds<M,sDCAnDCSnmdb.vdjj dcms.fedn dcnjdcskbjkfbedjbfrjbdjvfbjdcbcbdckjbkjdcbjdcdcjdkjcbjdcbbcdckjbjbdjjbdcjkdsx m mxX<Mmnc.,mcdcmnmdcm,m<MNCXnC<,mnNN<,m<MNXZnxnNnmXnNXnnnxnxnnxmnnxxnbnXNBnxXkjdsbjkeds ' # <- 16 bytes

for i in range (1000):
     computation={}
     #The Hash function
     hashStartTime=time.time()
     h = hashlib.sha256()
     h.update(message)
     digest=h.hexdigest()
     hashEndTime=time.time()
     hashExecutionTime=hashEndTime-hashStartTime
     computation["Hash time"] = hashExecutionTime
     
     # The HMAC function (SHA256)
     secret = b'Swordfish'
     HMACStartTime=time.time()
     h = hmac.new(secret,message, hashlib.sha256)
     digestHMAC=h.hexdigest()
     HMACEndTime=time.time()
     HMACExecutionTime=HMACEndTime-HMACStartTime
     computation["HMAC Execution time"] =  HMACExecutionTime
     
     RandomStartTime=time.time()
     random = os.urandom(1024)
     RandomEndTime=time.time()
     RandomExecutionTime=RandomEndTime-RandomStartTime
     computation["Random Execution time"] = RandomExecutionTime
     
     key = b'MyKeyCryptoLabqwertyasdfasdfzxcv'
     iv = Random.new().read(AES.block_size)
     AESencryptionStartTime=time.time()
     aes = AES.new(key, AES.MODE_CBC, iv)
     encd = aes.encrypt(message)
     AESencryptionEndTime=time.time()
     AESEncryptionTime=AESencryptionEndTime-AESencryptionStartTime
     computation["AES Encryption time"] = AESEncryptionTime
     
         
     # The bilinear pairing
     G = bp.BpGroup()
     bilinearPairingStartTime=time.time()
     g1, g2 = G.gen1(), G.gen2()     
     result1 = G.pair(g1, 6*g2)
     bilinearPairingEndTime=time.time()    
     bilinearPairingTime=bilinearPairingEndTime-bilinearPairingStartTime
     computation["Bilinear time"] =  bilinearPairingTime
     
     # The exponentiation operation
     a = 2988348162058574136915891421498819466320163312926952423791023078876139
     b = 2351399303373464486466122544523690094744975233415544072992656881240319
     m = 1234567891234567891215454614644315454654361548567464155456451454434446
     ExponentialStartTime=time.time()
     pow(a, b, m)    
     ExponentialEndTime=time.time()    
     ExponentialTime=ExponentialEndTime-ExponentialStartTime
     computation["Exponential Time"] =  ExponentialTime
     
     # The elliptic curve operations
     xs = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
     ys = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
     S = Point(xs, ys, curve=P256)

     xt = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
     yt = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
     T = Point(xt, yt, curve=P256)
     
     ECCadditionStartTime=time.time()
     S + T
     ECCadditionEndTime=time.time() 
     ECCTadditionTime=ECCadditionEndTime-ECCadditionStartTime
     computation["ECC Addition Time"] = ECCTadditionTime
     
     d = 0xc51f
     ###########
     ECCscalarMultiplicationStartTime=time.time()
     # The ECC scalar Multiplication operation
     R = d * S  
     ECCscalarMultiplicationEndTime=time.time()    
     EECCscalarMultiplicationTime=ECCscalarMultiplicationEndTime-ECCscalarMultiplicationStartTime
     computation["ECC Scalar Multiplication Time"] = EECCscalarMultiplicationTime
     data.append(computation)    

# Writing to JSON file
with open('PrimitiveComputationTime.csv', 'w') as json_file:
    json_file.write("Hash time"+","+"HMAC Execution time" +","+"Random Execution time"+","+"AES Encryption time"+","+
                        "Bilinear time"+","+"Exponential Time" +","+"ECC Addition Time"+","+"ECC Scalar Multiplication Time"+"\n")
    for each in data:
        json_file.write(str(each["Hash time"])+","+str(each["HMAC Execution time"]) +","+str(each["Random Execution time"])+","+str(each["AES Encryption time"])+","+
                        str(each["Bilinear time"])+","+str(each["Exponential Time"]) +","+str(each["ECC Addition Time"])+","+str(each["ECC Scalar Multiplication Time"])+"\n")
