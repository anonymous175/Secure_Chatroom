# Secure_Chatroom
This Program is written by Noone_1 and It's written in Python using most important Libraries and Methods. Using this program you can chat over a network like IRC(INternet Relay Chat ) but its more secure than it. Here first you have to generate key which is more secure and in created in openssl library. Both users can chat with secure connection that no one can intercept it.

Method to Use it:

You have to install these libraries:
 1. socket
 2. ssl
 3. threading
 4. sys
 5. os
 6. argparse
 7. subprocess

Commands:
1. python3 openssl-improved.py --generate-keys client
2. python3 openssl-improved.py --generate-keys server
3. python3 openssl-improved.py server <client's_ip> <port>
4. python3 openssl-improved.py client <server's_ip> <port>
