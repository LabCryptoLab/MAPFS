from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey

from fastecdsa.curve import P256
from fastecdsa.point import Point
from ecdsa.util import PRNG

import hashlib

import os 

import time

from mod import Mod

data=[]


#The Generation of the IoT keys 
x_a_priv_key, X_A_pub_key = keys.gen_keypair(curve.P256)
y_a_priv_key, Y_A_pub_key = keys.gen_keypair(curve.P256)

#The Generation of the gateway keys
x_w_priv_key, X_w_pub_key = keys.gen_keypair(curve.P256)
y_w_priv_key, Y_w_pub_key = keys.gen_keypair(curve.P256) 

#The Generation of the CA keys
s_rc_priv_key, Pub_rc_key = keys.gen_keypair(curve.P256)
s_IoT_priv_key, P_IoT_key = keys.gen_keypair(curve.P256)

#The Generation of the IoT identity
IoT_Identity=os.urandom(1024)

# The hash function
X_A_pub_key_xValue=X_A_pub_key.x.to_bytes(32, 'big')
X_A_pub_key_yValue=X_A_pub_key.y.to_bytes(32, 'big')

Y_A_pub_key_xValue=Y_A_pub_key.x.to_bytes(32, 'big')
Y_A_pub_key_yValue=Y_A_pub_key.y.to_bytes(32, 'big')

Pub_rc_key_xValue=Pub_rc_key.x.to_bytes(32, 'big')
Pub_rc_key_yValue=Pub_rc_key.y.to_bytes(32, 'big')

h0 = hashlib.new('sha256')
h0.update(X_A_pub_key_xValue+X_A_pub_key_yValue+Y_A_pub_key_xValue+Y_A_pub_key_yValue+Pub_rc_key_xValue+Pub_rc_key_yValue)
HashResult=h0.hexdigest()
HashInt=int(HashResult,16)
h_a=HashInt%P256.q

sigmaA=(s_IoT_priv_key+h_a*y_a_priv_key+y_a_priv_key)%P256.q

assert sigmaA*P256.G==(P_IoT_key+h_a*Y_A_pub_key+Y_A_pub_key), "The verification of the IoT authentication token has failed"

# The hash function
X_w_pub_key_xValue=X_w_pub_key.x.to_bytes(32, 'big')
X_w_pub_key_yValue=X_w_pub_key.y.to_bytes(32, 'big')

Pub_rc_key_xValue=Pub_rc_key.x.to_bytes(32, 'big')
Pub_rc_key_yValue=Pub_rc_key.y.to_bytes(32, 'big')

Y_w_pub_key_xValue=Y_w_pub_key.x.to_bytes(32, 'big')
Y_w_pub_key_yValue=Y_w_pub_key.y.to_bytes(32, 'big')

h1 = hashlib.new('sha256')
h1.update(X_w_pub_key_xValue+X_w_pub_key_yValue+Pub_rc_key_xValue+Pub_rc_key_yValue+Y_w_pub_key_xValue+Y_w_pub_key_yValue)
HashResult=h1.hexdigest()
HashInt=int(HashResult,16)
h_w=HashInt%P256.q
sigmaW=(s_rc_priv_key+h_w*y_w_priv_key)%P256.q

assert sigmaW*P256.G==(Pub_rc_key+h_w*Y_w_pub_key), "The verification of the gateway authentication token has failed"


for i in range (1000):
    computation=[]
    gatewayComputationTime=0
    IoTComputationTime=0
    
    # The IoT computation  
    rng_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
    rng_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
    rng_3 = int.from_bytes(os.urandom(1024),'big')%P256.q
    rng_4 = int.from_bytes(os.urandom(1024),'big')%P256.q

    A=rng_1*X_A_pub_key

    #########################################################
    ########### The protocol ################################
    #########################################################

    #########################################################
    ############# The Gateway computation ###################
    #########################################################

    GatewayStartTime=time.time()

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

    GatewayEndTime=time.time()
    gatewayComputationTime=GatewayEndTime-GatewayStartTime

    ########################################################
    ################# The IoT computation ##################
    ########################################################

    IoTStartTime=time.time()

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

    IoTEndTime=time.time()
    IoTComputationTime=IoTEndTime-IoTStartTime

    #####################################################
    ############## The Gateway computation  #############
    ##################################################### 

    GatewayStartTime=time.time()

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

    assert K_s_IoT==K_s_gateway, "Protocol: Failing in session key agreement"

    GatewayEndTime=time.time()
    gatewayComputationTime = gatewayComputationTime+(GatewayEndTime-GatewayStartTime)

    IoTComputation={"IoT Computation time": IoTComputationTime}
    gatewayComputation={"Gateway Computation time": gatewayComputationTime}

    computation.append(IoTComputation)
    computation.append(gatewayComputation)
    data.append(computation)


#writing to Json file 
with open('ProtocolComputationTime.csv','w') as json_file:
    json_file.write("IoT Computation time"+","+"Gateway Computation time"+"\n")

    for each in data:
        json_file.write(str(each[0]["IoT Computation time"]) + "," + str(each[1]["Gateway Computation time"]) + "\n")
