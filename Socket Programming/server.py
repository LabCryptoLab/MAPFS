import argparse
import socket, pickle
import os
import hashlib

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey
import hashlib
import time
from mod import Mod

# The HMAC function
from Crypto.Hash import HMAC
import hmac

# The IoT gateway secrets and keys
sigmaW = 78894563400529318085105683684609002255750380675253226777867014670183976137935
h_w = 7260728587595571176940947423883764002086369611242750794556056714335904520135

x_w_priv_key = 17922523504664817173877688169463668833456327911067154891176932840207341882409
X_w_pub_key_X = 0x40b2ee68a907803290524fc71657d7286e816c69709173fb5c8aff64994fa98a
X_w_pub_key_Y = 0xa08a447ea97a001177471dfa0e20215c8ebf22f42f8fb3eebaa8049d2a03fa5d
X_w_pub_key=Point(X_w_pub_key_X, X_w_pub_key_Y, curve=P256)


y_w_priv_key = 48943770448275109437494176028374417248266290101981699475691061188968403701176
Y_w_pub_key_X = 0x9f884e292f532418bf87660d9bb7942beb645b0a6e634bf4a0a85e609fc990d1
Y_w_pub_key_Y = 0xae31f340abc9ca61d4fd654270fd980952ff30fd5bb47a5869e1f4aa594e8281
Y_w_pub_key=Point(Y_w_pub_key_X, Y_w_pub_key_Y, curve=P256)

# The CA public keys  
Pub_rc_key_X = 0x460afc46f786a2c65f8eb1ab53dc78bbb5a3d727c07b376583fc53a2c0fbad2f
Pub_rc_key_Y = 0x8ab88486f15f434fad2167f9b9faf1a7520f0c63637691fbae01e00fa2c021cb
Pub_rc_key = Point(Pub_rc_key_X, Pub_rc_key_Y, curve=P256)

P_IoT_key_X = 0x7b8a7583d4f8222d5ea185fd4762d9e0bc98109d283c022b7a58be956809e982
P_IoT_key_Y = 0x4bab40aafab3b1f2062913290287e448c9eae0c028b8dae341aaf9c47ed2032b
P_IoT_key=Point(P_IoT_key_X, P_IoT_key_Y, curve=P256)

h = hashlib.sha256()


def server_program():
    # get the hostname
    host = '0.0.0.0'
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(10)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    
    while True:
        
        # step 1: receive hello
        IoT_HelloMsg = conn.recv(2048)
        if not IoT_HelloMsg:
            # if data is not received break
            break

        # Doing the Gateway computation after receiving the Hello message from the IoT device
        generatedData = generatingGatewayAuthToken(pickle.loads(IoT_HelloMsg))   
        GatewayAuthToken = generatedData[0:4]
       

        # Step 2: send gateway_auth token to the IoT device    # data contains: W, X_w_pub_key, Y_w_pub_key, sigmaZ
        conn.send(pickle.dumps(GatewayAuthToken))  # send data to the client
       
        # Step 3: receive msg_iot_auth
        # data contains: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2
        IoT_AuthToken = conn.recv(2048)
        if not IoT_AuthToken:
            # if data3 is not received break
            break

        # Doing the Gateway computation after receiving the IoT authentication token from the IoT device
        IoT_Authentication(GatewayAuthToken[0], pickle.loads(IoT_HelloMsg), pickle.loads(IoT_AuthToken),generatedData[4])

    conn.close()  # close the connection

#########################################################
############# The Gateway computation ###################
#########################################################
def generatingGatewayAuthToken(HelloData):

# initializing the sent A
    A = Point(HelloData.x, HelloData.y, curve=P256)

    #generating the r5
    rng_5 = int.from_bytes(os.urandom(1024),'big')%P256.q
    W=rng_5*X_w_pub_key

    # The hash function
    A_xValue=A.x.to_bytes(32, 'big')
    A_yValue=A.y.to_bytes(32, 'big')
    W_xValue=W.x.to_bytes(32, 'big')
    W_yValue=W.y.to_bytes(32, 'big')

    h2 = hashlib.new('sha256')
    h2.update(A_xValue+A_yValue+W_xValue+W_yValue)
    HashResult=h2.hexdigest()
    HashInt=int(HashResult,16)
    I_g=HashInt%P256.q

    sigmaZ=(I_g*sigmaW+rng_5*x_w_priv_key)%P256.q
    
    return W, X_w_pub_key, Y_w_pub_key, sigmaZ, rng_5


def IoT_Authentication(W, HelloData, IoT_AuthToken, rng_5):
    
    #data contains: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2

    # initializing the sent P_1
    P_1 = Point(IoT_AuthToken[0].x, IoT_AuthToken[0].y, curve=P256)
    
    # initializing the sent P_2
    P_2 = Point(IoT_AuthToken[1].x, IoT_AuthToken[1].y, curve=P256)

    # initializing the sent P_3
    P_3 = Point(IoT_AuthToken[2].x, IoT_AuthToken[2].y, curve=P256)

    sigma_t = IoT_AuthToken[3]

    # initializing the sent T_1
    T_1 = Point(IoT_AuthToken[4].x, IoT_AuthToken[4].y, curve=P256)

    # initializing the sent T_2
    T_2 = Point(IoT_AuthToken[5].x, IoT_AuthToken[5].y, curve=P256)

    s_1 = IoT_AuthToken[6]
    s_2 = IoT_AuthToken[7]
    
    # initializing the sent A
    A = Point(HelloData.x, HelloData.y, curve=P256)
    
    # initializing the sent W
    W = Point(W.x, W.y, curve=P256)
    
    ################## I_a computation ##################

    A_xValue=A.x.to_bytes(32, 'big')
    A_yValue=A.y.to_bytes(32, 'big')
    P_1_xValue=P_1.x.to_bytes(32, 'big')
    P_1_yValue=P_1.y.to_bytes(32, 'big')
    P_2_xValue=P_2.x.to_bytes(32, 'big')
    P_2_yValue=P_2.y.to_bytes(32, 'big')
    P_3_xValue=P_3.x.to_bytes(32, 'big')
    P_3_yValue=P_3.y.to_bytes(32, 'big')
    T_1_xValue=T_1.x.to_bytes(32, 'big')
    T_1_yValue=T_1.y.to_bytes(32, 'big')
    T_2_xValue=T_2.x.to_bytes(32, 'big')
    T_2_yValue=T_2.y.to_bytes(32, 'big')
    W_xValue=W.x.to_bytes(32, 'big')
    W_yValue=W.y.to_bytes(32, 'big')

    h6 = hashlib.new('sha256')
    h6.update(A_xValue+A_yValue+P_1_xValue+P_1_yValue+P_2_xValue+P_2_yValue+P_3_xValue+P_3_yValue+T_1_xValue+T_1_yValue+T_2_xValue+T_2_yValue+W_xValue+W_yValue)
    HashResult=h6.hexdigest()
    HashInt=int(HashResult,16)
    I_a=HashInt%P256.q

    assert sigma_t*P256.G==(I_a*P_1+I_a*P_2+I_a*P_3+A), "Protocol: Failed in authenticating the IoT device"
    assert s_1*P_IoT_key==(I_a*P_2+T_1), "Protocol: Failed in verifying P_IoT"
    assert s_2*P_1==(I_a*P_3+T_2), "Protocol: Failed in verifying P_1"

    # The hash function H_0(r_5x_wA)
    A_xValue=(rng_5*x_w_priv_key*A).x.to_bytes(32, 'big')
    A_yValue=(rng_5*x_w_priv_key*A).y.to_bytes(32, 'big')

    h7 = hashlib.new('sha256')
    h7.update(A_xValue+A_yValue)
    HashResult=h7.hexdigest()
    HashInt=int(HashResult,16)
    K_s_gateway=HashInt%P256.q
    
 
    
if __name__ == '__main__':
    server_program()
