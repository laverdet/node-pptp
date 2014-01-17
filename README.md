# node-pptp
Simple PPTP VPN server I started working on for a project, but ultimately abandoned. Maybe this will
be useful for someone.

Features:
* No authentication; credentials are not requested.
* No encryption.
* IPv4 only.
* Unreliable handshake. No retransmission is implemented so if there is a single missed packet the
  handshake will timeout.
* After established, though, the connection is fairly reliable.
* Only tested with, and probably only works with, OS X clients.
* Runs on OS X & Linux

Note that the VPN does not create a network device on the server for incoming clients. Instead the
client is simply a NodeJS object that you can send and receive IPv4 frames to directly. If you
want to create a network device for your client (say for IP forwarding via iptables MASQ) you can
use tun/tap fairly easily. All clients are assigned a hardcoded IP address of 10.0.1.2 and expect a
gateway of 10.0.1.1, though these selections are arbitrary.

Also note that connecting to a VPN server on localhost seems to be broken on OS X. If you connect
through 127.0.0.1/localhost the handshake will fail completely. If you connect through another IP
address the VPN connection is successfully created but the kernel doesn't seem to like routing GRE
frames from a loopback device. I tried very hard to work around this and it seems like a problem
inherent to the Darwin kernel; this was the main reason I abandoned the project. I guess there's
not really many reasons for anyone to connect to a PPTP server on localhost.

Included in the repository is a VPN server which will send ping responses from any host you ping.
All other frames are ignored.

# Setup
## Server
```sh
git clone https://github.com/laverdet/node-pptp.git
cd node-pptp
npm install # installs raw-socket & pcap npm modules; required for VPN
sudo node example # root is required
```

## Client
* **OS X PPTP VPN**
* Account Name: _anything_
  * Encryption: _None_
  * **Authentication Settings...**
    * Password: _anything_

```txt
marcel@marcel ~ $ ping 1.2.3.4
PING 1.2.3.4 (1.2.3.4): 56 data bytes
64 bytes from 1.2.3.4: icmp_seq=0 ttl=64 time=71.156 ms
64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=72.612 ms
64 bytes from 1.2.3.4: icmp_seq=2 ttl=64 time=72.775 ms
```
