# MAPFS
This is a python implementation of our protocol MAAFS (Mutual Authentication Privacy-preserving protocol with Forward Secrecy) for the IoT-edge-cloud paradigm. Our implementation consists of three parts.
## The Cryptographic Primitives Timing 
The timing measuring of the used cryptographic primitives in our protocal such as SHA-256 hash function, HMAC function, AES-CBC mode encryption, bilinear pairing, EC scalar multiplication and EC point addition.
## The Protocol Implementation
The implementation of the protocol where the registration token for the IoT device and the IoT gateway are generated to simulate the registration phase. Afterwards, the protocol is executed between the IoT device and the IoT gateway where each entity exchanges its authentication token and authenticates the other entity. This implementation shows the completeness of our proposed protocol and proves it effectiveness while running on a ressource-constrained device such as the Raspberry Pi 4. 
## The Socket Programming
The implementation of a socket programming to simulate the flow of authentication tokens between the IoT device and the IoT gateway and get the overall time considering the network time. The client, a Raspberry Pi 4 equipped with a 1.5 GHz 64-bit Quad-core ARM Cortex-A72 processor running Raspbian GNU/Linux 11 (bullseye), played the role of the IoT device, and the server, an Intel laptop 11th Gen Core i7-11800H clocked at 2.3 GHz with 16 GB RAM running Windows 11, acted as the IoT gateway.

## Running the demo

The communication runs over a tcp connection on port 5000. Make sure this port is open in the firewall.

First install the requirements:
```
pip3 install -r requirements.txt
```

First start the server on the gateway machine:
```
cd "Socket Programming"
python server.py
```

Then start the client on the iot device, specifiying the gateway's ip address
```
cd "Socket Programming"
python client -c <ip.of.gateway>
```

