###   To Connect to the laptop server from the raspberry pi,run: 
###
###   python client.py -c 169.254.69.248
###
###   To Connect to the raspberry pi server from the laptop, run: 
###
###   python client.py -c 169.254.232.12

import argparse
import socket, pickle
import os
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

# The generated Keys of the IoT device and the CA

sigmaA = 39369573487838701846037597157602507926051317739817887174176923988022843530038
h_a = 42004559467750234637944250031145365341743669710328000514075203351893538629734

x_a_priv_key = 36369948938032464995087178169496231302783312692229819844358113796571722124176
X_A_pub_key_X = 0xbf4499a77770e079d7837cbe5b1f63631ec6c52198216a6c1a606bf5b7d1b1e3
X_A_pub_key_Y = 0x418086f9ecbafedc79c93f35995c7c56deb2d90fe03fd9434fb28bec5fde0b03
X_A_pub_key=Point(X_A_pub_key_X, X_A_pub_key_Y, curve=curve.P256)

# y_a_priv_key = 18007808170234709668614628959590804361121746045131466250275547727245659092469
Y_A_pub_key_X = 0xe547d3d1170080794dcb0b61db7036ca944c808e62cedd3109759e7bfaab7edd
Y_A_pub_key_Y = 0x30ae71a32a3d51819c740f457dad65905cb201e5bdc77e2b5248250ca2026f49
Y_A_pub_key = Point(Y_A_pub_key_X, Y_A_pub_key_Y, curve=curve.P256)

Pub_rc_key_X = 0x460afc46f786a2c65f8eb1ab53dc78bbb5a3d727c07b376583fc53a2c0fbad2f
Pub_rc_key_Y = 0x8ab88486f15f434fad2167f9b9faf1a7520f0c63637691fbae01e00fa2c021cb
Pub_rc_key = Point(Pub_rc_key_X, Pub_rc_key_Y, curve=curve.P256)

P_IoT_key_X = 0x7b8a7583d4f8222d5ea185fd4762d9e0bc98109d283c022b7a58be956809e982
P_IoT_key_Y = 0x4bab40aafab3b1f2062913290287e448c9eae0c028b8dae341aaf9c47ed2032b
P_IoT_key=Point(P_IoT_key_X, P_IoT_key_Y, curve=curve.P256)


#Global Values
#########################################################
###### The IoT computation for the Hello Message  #######
#########################################################

IoTStartTime=time.time()

rng_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_3 = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_4 = int.from_bytes(os.urandom(1024),'big')%P256.q

A=rng_1*X_A_pub_key


# The Socket programming
parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='server to connect to') 
args = parser.parse_args()

def client_program():
    host = args.connect # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    message = ""

    # while message.lower().strip() != 'bye':
        
    # Step 1: Send hello
    message = hello()
    client_socket.send(pickle.dumps(message))  # send message
    IoTEndTime=time.time()
    print('IoT device: step 1: sent to gateway: ' + str(message))
    
    #Step 2: Receive the gateway authentication token # data contains: W, X_w_pub_key, Y_w_pub_key, sigmaZ
    data = client_socket.recv(2048)         
    print('IoT device: step 2: received from gateway: ')
    print(pickle.loads(data))  # show in terminal

    #do the IoT computation 2 and send the authentication token to the gateway
    # Message contains: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2
    message = gatewayAuthOnTheIoT_Side(pickle.loads(data))
    client_socket.send(pickle.dumps(message))
    print('IoT device: Step 3: sent to gateway: ' + str(message))       
    client_socket.close()  # close the connection


def hello():
    return A
     
def gatewayAuthOnTheIoT_Side(GatewayAuthToken):
    # data contains: W, X_w_pub_key, Y_w_pub_key, sigmaZ
       
    # initializing the sent W
    W = Point(GatewayAuthToken[0].x, GatewayAuthToken[0].y, curve=P256)
    
    #initializing the sent X_w_pub_key
    X_w_pub_key = Point(GatewayAuthToken[1].x, GatewayAuthToken[1].y, curve=P256)

    #initializing the sent Y_w_pub_key
    Y_w_pub_key = Point(GatewayAuthToken[2].x, GatewayAuthToken[2].y, curve=P256)

    sigmaZ = GatewayAuthToken[3]

    ######### computation of the I_g
    A_xValue=A.x.to_bytes(32, 'big')
    A_yValue=A.y.to_bytes(32, 'big')
    W_xValue=W.x.to_bytes(32, 'big')
    W_yValue=W.y.to_bytes(32, 'big')

    h3 = hashlib.new('sha256')
    h3.update(A_xValue+A_yValue+W_xValue+W_yValue)
    HashResult=h3.hexdigest()
    HashInt=int(HashResult,16)
    I_g=HashInt%P256.q

    ######## Computation of the H_1
    X_w_pub_key_xValue=X_w_pub_key.x.to_bytes(32, 'big')
    X_w_pub_key_yValue=X_w_pub_key.y.to_bytes(32, 'big')

    Pub_rc_key_xValue=Pub_rc_key.x.to_bytes(32, 'big')
    Pub_rc_key_yValue=Pub_rc_key.y.to_bytes(32, 'big')

    Y_w_pub_key_xValue=Y_w_pub_key.x.to_bytes(32, 'big')
    Y_w_pub_key_yValue=Y_w_pub_key.y.to_bytes(32, 'big')

    h4 = hashlib.new('sha256')
    h4.update(X_w_pub_key_xValue+X_w_pub_key_yValue+Pub_rc_key_xValue+Pub_rc_key_yValue+Y_w_pub_key_xValue+Y_w_pub_key_yValue)
    HashResult=h4.hexdigest()
    HashInt=int(HashResult,16)
    h_w=HashInt%P256.q
    
    assert sigmaZ*P256.G==(I_g*Pub_rc_key+I_g*h_w*Y_w_pub_key+W), "Protocol: Failing in authenticating the IoT gateway"

    # The hash function H_0(r_1x_aW)
    A_xValue=(rng_1*x_a_priv_key*W).x.to_bytes(32, 'big')
    A_yValue=(rng_1*x_a_priv_key*W).y.to_bytes(32, 'big')

    h5 = hashlib.new('sha256')
    h5.update(A_xValue+A_yValue)
    HashResult=h5.hexdigest()
    HashInt=int(HashResult,16)
    K_s_IoT=HashInt%P256.q
    
    P_1=rng_2*Y_A_pub_key
    P_2=rng_2*P_IoT_key
    P_3=rng_2*h_a*Y_A_pub_key
    T_1=rng_3*P_IoT_key
    T_2=rng_4*P_1

    # The hash function H_4(A,P_1,P_2,P_3,T_1,T_2,W)
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

    sigma_t=(I_a*rng_2*sigmaA+rng_1*x_a_priv_key)%P256.q
    s_1=(rng_2*I_a+rng_3)%P256.q
    s_2=(h_a*I_a+rng_4)%P256.q

    return P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2
    
if __name__ == '__main__':
    client_program()
